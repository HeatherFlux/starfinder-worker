// Durable Object for real-time hacking session sync
// Handles WebSocket connections between GM and players

import {
  validateComputer,
  validateNodeStatePayload,
  validateFocusPayload,
  validateIntensityPayload,
  validateMessageType,
  validateEffectPayload,
} from './validation'

// Types mirrored from the main app (includes SF2e hacking extensions)
type ComputerType = 'tech' | 'magic' | 'hybrid'
type AccessPointType = 'physical' | 'remote' | 'magical'
type NodeState = 'locked' | 'active' | 'breached' | 'alarmed'
type ProficiencyRank = 'untrained' | 'trained' | 'expert' | 'master' | 'legendary'

interface Position {
  x: number
  y: number
}

interface SkillCheck {
  skill: string
  dc: number
  proficiency?: ProficiencyRank
}

interface Vulnerability {
  id: string
  name: string
  skills: SkillCheck[]
  dcReduction: number
}

interface Countermeasure {
  id: string
  name: string
  failureThreshold: number
  noticeDC?: number
  noticeSkills?: string[]
  disableSkills: SkillCheck[]
  description: string
  isPersistent?: boolean
}

interface AccessPoint {
  id: string
  name: string
  type: AccessPointType
  state: NodeState
  position: Position
  connectedTo: string[]
  // SF2e extended fields
  dc?: number
  successesRequired?: number
  hackSkills?: SkillCheck[]
  vulnerabilities?: Vulnerability[]
  countermeasures?: Countermeasure[]
  currentFailures?: number
}

interface Computer {
  id: string
  name: string
  level: number
  type: ComputerType
  description?: string
  accessPoints: AccessPoint[]
  // SF2e outcome descriptions
  successDescription?: string
  criticalSuccessDescription?: string
}

interface SessionState {
  computer: Computer | null
  focusedNodeId: string | null
  ambientIntensity: number
  lastActivity: number
}

interface ClientInfo {
  role: 'gm' | 'player'
  messageTimestamps: number[]  // For rate limiting
}

// Limits
const MAX_CONNECTIONS = 20
const RATE_LIMIT_WINDOW_MS = 10_000  // 10 seconds
const RATE_LIMIT_MAX_MESSAGES = 50   // 50 messages per window

type MessageType =
  | 'effect'
  | 'node-state'
  | 'focus'
  | 'intensity'
  | 'computer'
  | 'clear-effects'
  | 'ping'
  | 'init'
  | 'pong'

interface SyncMessage {
  type: MessageType
  payload: unknown
}

export class HackingSession implements DurableObject {
  private state: DurableObjectState
  private sessions: Map<WebSocket, ClientInfo> = new Map()

  // Session state
  private computer: Computer | null = null
  private focusedNodeId: string | null = null
  private ambientIntensity: number = 0.7

  constructor(state: DurableObjectState, _env: unknown) {
    this.state = state

    // Restore state from storage on wake
    this.state.blockConcurrencyWhile(async () => {
      const stored = await this.state.storage.get<SessionState>('state')
      if (stored) {
        this.computer = stored.computer
        this.focusedNodeId = stored.focusedNodeId
        this.ambientIntensity = stored.ambientIntensity
      }
    })
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url)

    // WebSocket upgrade
    if (request.headers.get('Upgrade') === 'websocket') {
      const role = (url.searchParams.get('role') as 'gm' | 'player') || 'player'
      return this.handleWebSocket(role)
    }

    // REST endpoint for debugging - get current state
    if (url.pathname.endsWith('/state')) {
      return new Response(JSON.stringify({
        computer: this.computer,
        focusedNodeId: this.focusedNodeId,
        ambientIntensity: this.ambientIntensity,
        connections: this.sessions.size
      }), {
        headers: { 'Content-Type': 'application/json' }
      })
    }

    return new Response('Not Found', { status: 404 })
  }

  private sendError(ws: WebSocket, code: string, message: string): void {
    try {
      ws.send(JSON.stringify({ type: 'error', payload: { code, message } }))
    } catch {
      // Socket may be closed, ignore
    }
  }

  private handleWebSocket(role: 'gm' | 'player'): Response {
    // Enforce connection limit
    if (this.sessions.size >= MAX_CONNECTIONS) {
      return new Response('Too many connections', { status: 503 })
    }

    const pair = new WebSocketPair()
    const [client, server] = Object.values(pair)

    // Accept the WebSocket connection
    this.state.acceptWebSocket(server, [role])
    this.sessions.set(server, { role, messageTimestamps: [] })

    // Send current state to new connection
    server.send(JSON.stringify({
      type: 'init',
      payload: {
        computer: this.computer,
        focusedNodeId: this.focusedNodeId,
        ambientIntensity: this.ambientIntensity
      }
    } as SyncMessage))

    // Reset inactivity alarm
    this.scheduleCleanup()

    console.log(`[HackingSession] ${role} connected. Total: ${this.sessions.size}`)

    return new Response(null, {
      status: 101,
      webSocket: client
    })
  }

  private checkRateLimit(client: ClientInfo): boolean {
    const now = Date.now()
    // Remove timestamps outside the window
    client.messageTimestamps = client.messageTimestamps.filter(
      ts => now - ts < RATE_LIMIT_WINDOW_MS
    )
    // Check if over limit
    if (client.messageTimestamps.length >= RATE_LIMIT_MAX_MESSAGES) {
      return false
    }
    client.messageTimestamps.push(now)
    return true
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    // Get role from WebSocket tags (survives hibernation, unlike the Map)
    const tags = this.state.getTags(ws)
    const role = tags.includes('gm') ? 'gm' : 'player'

    // Ensure sender is in sessions map (may have been cleared by hibernation)
    let sender = this.sessions.get(ws)
    if (!sender) {
      sender = { role, messageTimestamps: [] }
      this.sessions.set(ws, sender)
    }

    // Rate limiting
    if (!this.checkRateLimit(sender)) {
      this.sendError(ws, 'RATE_LIMITED', 'Too many messages, slow down')
      console.warn('[HackingSession] Rate limited client')
      return
    }

    // Reject binary messages
    if (typeof message !== 'string') {
      this.sendError(ws, 'INVALID_FORMAT', 'Binary messages not supported')
      console.warn('[HackingSession] Rejected binary message')
      return
    }

    // Reject oversized messages (max 100KB)
    if (message.length > 100_000) {
      this.sendError(ws, 'MESSAGE_TOO_LARGE', 'Message exceeds 100KB limit')
      console.warn('[HackingSession] Rejected oversized message:', message.length)
      return
    }

    let data: SyncMessage
    try {
      data = JSON.parse(message)
    } catch {
      this.sendError(ws, 'INVALID_JSON', 'Message is not valid JSON')
      console.warn('[HackingSession] Invalid JSON message')
      return
    }

    // Validate message type
    const messageType = validateMessageType(data.type)
    if (!messageType) {
      this.sendError(ws, 'INVALID_TYPE', `Unknown message type: ${data.type}`)
      console.warn('[HackingSession] Invalid message type:', data.type)
      return
    }

    // Handle ping from any client
    if (messageType === 'ping') {
      ws.send(JSON.stringify({ type: 'pong', payload: Date.now() }))
      return
    }

    // Only GM can send state changes
    if (sender.role !== 'gm') {
      this.sendError(ws, 'UNAUTHORIZED', 'Only GM can modify session state')
      console.log('[HackingSession] Non-GM tried to send:', messageType)
      return
    }

    // Validate and update local state based on message type
    let validatedPayload: unknown = data.payload

    switch (messageType) {
      case 'computer': {
        const result = validateComputer(data.payload)
        if (!result.valid) {
          this.sendError(ws, 'INVALID_PAYLOAD', result.error)
          console.warn('[HackingSession] Invalid computer payload:', result.error)
          return
        }
        this.computer = result.value
        validatedPayload = result.value
        break
      }

      case 'node-state': {
        const result = validateNodeStatePayload(data.payload)
        if (!result.valid) {
          this.sendError(ws, 'INVALID_PAYLOAD', result.error)
          console.warn('[HackingSession] Invalid node-state payload:', result.error)
          return
        }
        if (this.computer) {
          const node = this.computer.accessPoints.find(ap => ap.id === result.value.nodeId)
          if (node) {
            node.state = result.value.state
          }
        }
        validatedPayload = result.value
        break
      }

      case 'focus': {
        const result = validateFocusPayload(data.payload)
        if (!result.valid) {
          this.sendError(ws, 'INVALID_PAYLOAD', result.error)
          console.warn('[HackingSession] Invalid focus payload:', result.error)
          return
        }
        this.focusedNodeId = result.value.nodeId
        validatedPayload = result.value
        break
      }

      case 'intensity': {
        const result = validateIntensityPayload(data.payload)
        if (!result.valid) {
          this.sendError(ws, 'INVALID_PAYLOAD', result.error)
          console.warn('[HackingSession] Invalid intensity payload:', result.error)
          return
        }
        this.ambientIntensity = result.value.value
        validatedPayload = result.value
        break
      }

      case 'effect': {
        const result = validateEffectPayload(data.payload)
        if (!result.valid) {
          this.sendError(ws, 'INVALID_PAYLOAD', result.error)
          console.warn('[HackingSession] Invalid effect payload:', result.error)
          return
        }
        validatedPayload = result.value
        // Effects don't persist, just broadcast
        break
      }

      case 'clear-effects':
        // Just broadcast
        break
    }

    // Use validated payload in broadcast
    data = { type: messageType as MessageType, payload: validatedPayload }

    // Persist state (skip for transient messages like effects)
    if (data.type !== 'effect' && data.type !== 'clear-effects') {
      await this.state.storage.put<SessionState>('state', {
        computer: this.computer,
        focusedNodeId: this.focusedNodeId,
        ambientIntensity: this.ambientIntensity,
        lastActivity: Date.now()
      })
    }

    // Broadcast to all OTHER connections (not back to sender)
    // Use getWebSockets() to get all connections (survives hibernation)
    const messageStr = JSON.stringify(data)
    for (const socket of this.state.getWebSockets()) {
      if (socket !== ws && socket.readyState === WebSocket.OPEN) {
        socket.send(messageStr)
      }
    }

    // Reset cleanup alarm on activity
    this.scheduleCleanup()
  }

  async webSocketClose(ws: WebSocket): Promise<void> {
    const info = this.sessions.get(ws)
    this.sessions.delete(ws)
    console.log(`[HackingSession] ${info?.role || 'unknown'} disconnected. Remaining: ${this.sessions.size}`)

    // If no connections remain, schedule cleanup
    if (this.sessions.size === 0) {
      this.scheduleCleanup()
    }
  }

  async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
    console.error('[HackingSession] WebSocket error:', error)
    this.sessions.delete(ws)
  }

  private async scheduleCleanup(): Promise<void> {
    // Set alarm 15 minutes from now
    const alarmTime = Date.now() + 15 * 60 * 1000
    await this.state.storage.setAlarm(alarmTime)
  }

  async alarm(): Promise<void> {
    // If still no connections after 15 min, clear state
    if (this.sessions.size === 0) {
      console.log('[HackingSession] Cleaning up inactive session')
      await this.state.storage.deleteAll()
      this.computer = null
      this.focusedNodeId = null
      this.ambientIntensity = 0.7
    } else {
      // Still have connections, reschedule
      this.scheduleCleanup()
    }
  }
}
