import { describe, it, expect } from 'vitest'
import {
  sanitizeString,
  sanitizeId,
  validateNumber,
  validateComputer,
  validateNodeStatePayload,
  validateNodeHiddenPayload,
  validateFocusPayload,
  validateIntensityPayload,
  validateMessageType,
  validateEffectPayload,
  LIMITS,
} from './validation'

// ============== sanitizeString ==============
describe('sanitizeString', () => {
  it('returns null for non-strings', () => {
    expect(sanitizeString(123)).toBeNull()
    expect(sanitizeString(null)).toBeNull()
    expect(sanitizeString(undefined)).toBeNull()
    expect(sanitizeString({})).toBeNull()
    expect(sanitizeString([])).toBeNull()
  })

  it('trims whitespace', () => {
    expect(sanitizeString('  hello  ')).toBe('hello')
    expect(sanitizeString('\n\thello\t\n')).toBe('hello')
  })

  it('escapes HTML entities to prevent XSS', () => {
    expect(sanitizeString('<script>alert("xss")</script>')).toBe(
      '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;'
    )
    expect(sanitizeString("it's a <test> & 'quote'")).toBe(
      "it&#x27;s a &lt;test&gt; &amp; &#x27;quote&#x27;"
    )
  })

  it('removes control characters', () => {
    expect(sanitizeString('hello\x00world')).toBe('helloworld')
    expect(sanitizeString('\x07beep\x08')).toBe('beep')
  })

  it('enforces max length', () => {
    const long = 'a'.repeat(1000)
    expect(sanitizeString(long, 10)?.length).toBe(10)
  })

  it('returns null for empty strings', () => {
    expect(sanitizeString('')).toBeNull()
    expect(sanitizeString('   ')).toBeNull()
  })
})

// ============== sanitizeId ==============
describe('sanitizeId', () => {
  it('returns null for non-strings', () => {
    expect(sanitizeId(123)).toBeNull()
    expect(sanitizeId(null)).toBeNull()
  })

  it('allows valid ID characters', () => {
    expect(sanitizeId('abc-123_XYZ')).toBe('abc-123_XYZ')
    expect(sanitizeId('node1')).toBe('node1')
  })

  it('rejects invalid characters', () => {
    expect(sanitizeId('id<script>')).toBeNull()
    expect(sanitizeId('id with spaces')).toBeNull()
    expect(sanitizeId('id/path')).toBeNull()
    expect(sanitizeId('../escape')).toBeNull()
  })

  it('enforces max length', () => {
    const long = 'a'.repeat(100)
    expect(sanitizeId(long)?.length).toBe(LIMITS.MAX_ID_LENGTH)
  })
})

// ============== validateNumber ==============
describe('validateNumber', () => {
  it('returns null for non-numbers', () => {
    expect(validateNumber('5')).toBeNull()
    expect(validateNumber(null)).toBeNull()
    expect(validateNumber(undefined)).toBeNull()
  })

  it('rejects NaN and Infinity', () => {
    expect(validateNumber(NaN)).toBeNull()
    expect(validateNumber(Infinity)).toBeNull()
    expect(validateNumber(-Infinity)).toBeNull()
  })

  it('enforces min/max bounds', () => {
    expect(validateNumber(5, 0, 10)).toBe(5)
    expect(validateNumber(-1, 0, 10)).toBeNull()
    expect(validateNumber(11, 0, 10)).toBeNull()
  })

  it('allows edge values', () => {
    expect(validateNumber(0, 0, 10)).toBe(0)
    expect(validateNumber(10, 0, 10)).toBe(10)
  })
})

// ============== validateComputer ==============
describe('validateComputer', () => {
  const validComputer = {
    id: 'comp-1',
    name: 'Test Computer',
    level: 5,
    type: 'tech',
    accessPoints: [
      {
        id: 'ap-1',
        name: 'Main Access',
        type: 'physical',
        state: 'locked',
        position: { x: 100, y: 200 },
        connectedTo: ['ap-2'],
      },
    ],
  }

  it('accepts valid computer objects', () => {
    const result = validateComputer(validComputer)
    expect(result.valid).toBe(true)
    if (result.valid) {
      expect(result.value.id).toBe('comp-1')
      expect(result.value.name).toBe('Test Computer')
    }
  })

  it('rejects invalid computer types', () => {
    const result = validateComputer({ ...validComputer, type: 'quantum' })
    expect(result.valid).toBe(false)
  })

  it('rejects out-of-range levels', () => {
    const result = validateComputer({ ...validComputer, level: 100 })
    expect(result.valid).toBe(false)
  })

  it('sanitizes name with XSS attempt', () => {
    const result = validateComputer({
      ...validComputer,
      name: '<script>alert("pwned")</script>',
    })
    expect(result.valid).toBe(true)
    if (result.valid) {
      expect(result.value.name).not.toContain('<script>')
      expect(result.value.name).toContain('&lt;script&gt;')
    }
  })

  it('rejects too many access points', () => {
    const manyPoints = Array(30).fill(validComputer.accessPoints[0])
    const result = validateComputer({
      ...validComputer,
      accessPoints: manyPoints,
    })
    expect(result.valid).toBe(false)
  })

  it('rejects invalid access point states', () => {
    const badAP = {
      ...validComputer.accessPoints[0],
      state: 'hacked',
    }
    const result = validateComputer({
      ...validComputer,
      accessPoints: [badAP],
    })
    expect(result.valid).toBe(false)
  })

  it('preserves hidden field on access points', () => {
    const result = validateComputer({
      ...validComputer,
      accessPoints: [{
        ...validComputer.accessPoints[0],
        hidden: true,
      }],
    })
    expect(result.valid).toBe(true)
    if (result.valid) {
      expect(result.value.accessPoints[0].hidden).toBe(true)
    }
  })

  it('rejects non-boolean hidden field', () => {
    const result = validateComputer({
      ...validComputer,
      accessPoints: [{
        ...validComputer.accessPoints[0],
        hidden: 'yes',
      }],
    })
    expect(result.valid).toBe(false)
  })

  it('omits hidden field when not provided', () => {
    const result = validateComputer(validComputer)
    expect(result.valid).toBe(true)
    if (result.valid) {
      expect(result.value.accessPoints[0].hidden).toBeUndefined()
    }
  })

  it('rejects null/undefined', () => {
    expect(validateComputer(null).valid).toBe(false)
    expect(validateComputer(undefined).valid).toBe(false)
  })
})

// ============== validateNodeStatePayload ==============
describe('validateNodeStatePayload', () => {
  it('accepts valid payloads', () => {
    const result = validateNodeStatePayload({ nodeId: 'node-1', state: 'breached' })
    expect(result.valid).toBe(true)
    if (result.valid) {
      expect(result.value.nodeId).toBe('node-1')
      expect(result.value.state).toBe('breached')
    }
  })

  it('rejects invalid node states', () => {
    expect(validateNodeStatePayload({ nodeId: 'node-1', state: 'hacked' }).valid).toBe(false)
    expect(validateNodeStatePayload({ nodeId: 'node-1', state: '' }).valid).toBe(false)
  })

  it('rejects invalid node IDs', () => {
    expect(validateNodeStatePayload({ nodeId: '<script>', state: 'locked' }).valid).toBe(false)
    expect(validateNodeStatePayload({ nodeId: '', state: 'locked' }).valid).toBe(false)
  })
})

// ============== validateNodeHiddenPayload ==============
describe('validateNodeHiddenPayload', () => {
  it('accepts valid payloads', () => {
    const result = validateNodeHiddenPayload({ nodeId: 'node-1', hidden: true })
    expect(result.valid).toBe(true)
    if (result.valid) {
      expect(result.value.nodeId).toBe('node-1')
      expect(result.value.hidden).toBe(true)
    }
  })

  it('accepts hidden=false', () => {
    const result = validateNodeHiddenPayload({ nodeId: 'node-1', hidden: false })
    expect(result.valid).toBe(true)
    if (result.valid) {
      expect(result.value.hidden).toBe(false)
    }
  })

  it('rejects non-boolean hidden field', () => {
    expect(validateNodeHiddenPayload({ nodeId: 'node-1', hidden: 'true' }).valid).toBe(false)
    expect(validateNodeHiddenPayload({ nodeId: 'node-1', hidden: 1 }).valid).toBe(false)
    expect(validateNodeHiddenPayload({ nodeId: 'node-1' }).valid).toBe(false)
  })

  it('rejects invalid node IDs', () => {
    expect(validateNodeHiddenPayload({ nodeId: '<script>', hidden: true }).valid).toBe(false)
    expect(validateNodeHiddenPayload({ nodeId: '', hidden: true }).valid).toBe(false)
  })

  it('rejects null/undefined', () => {
    expect(validateNodeHiddenPayload(null).valid).toBe(false)
    expect(validateNodeHiddenPayload(undefined).valid).toBe(false)
  })
})

// ============== validateFocusPayload ==============
describe('validateFocusPayload', () => {
  it('accepts valid node ID', () => {
    const result = validateFocusPayload({ nodeId: 'node-1' })
    expect(result.valid).toBe(true)
    if (result.valid) {
      expect(result.value.nodeId).toBe('node-1')
    }
  })

  it('accepts null for unfocusing', () => {
    const result = validateFocusPayload({ nodeId: null })
    expect(result.valid).toBe(true)
    if (result.valid) {
      expect(result.value.nodeId).toBeNull()
    }
  })

  it('rejects invalid node IDs', () => {
    expect(validateFocusPayload({ nodeId: '../escape' }).valid).toBe(false)
  })
})

// ============== validateIntensityPayload ==============
describe('validateIntensityPayload', () => {
  it('accepts values between 0 and 1', () => {
    expect(validateIntensityPayload({ value: 0 }).valid).toBe(true)
    expect(validateIntensityPayload({ value: 0.5 }).valid).toBe(true)
    expect(validateIntensityPayload({ value: 1 }).valid).toBe(true)
  })

  it('rejects values outside range', () => {
    expect(validateIntensityPayload({ value: -0.1 }).valid).toBe(false)
    expect(validateIntensityPayload({ value: 1.1 }).valid).toBe(false)
    expect(validateIntensityPayload({ value: 100 }).valid).toBe(false)
  })

  it('rejects NaN and Infinity', () => {
    expect(validateIntensityPayload({ value: NaN }).valid).toBe(false)
    expect(validateIntensityPayload({ value: Infinity }).valid).toBe(false)
  })

  it('rejects non-numbers', () => {
    expect(validateIntensityPayload({ value: '0.5' }).valid).toBe(false)
  })
})

// ============== validateMessageType ==============
describe('validateMessageType', () => {
  it('accepts valid message types', () => {
    const validTypes = ['effect', 'node-state', 'focus', 'intensity', 'computer', 'clear-effects', 'ping', 'pong', 'init', 'combat-state', 'request-state']
    for (const type of validTypes) {
      expect(validateMessageType(type)).toBe(type)
    }
  })

  it('accepts combat sync message types', () => {
    expect(validateMessageType('combat-state')).toBe('combat-state')
    expect(validateMessageType('request-state')).toBe('request-state')
  })

  it('accepts node-hidden message type', () => {
    expect(validateMessageType('node-hidden')).toBe('node-hidden')
  })

  it('accepts all starship sync message types', () => {
    const starshipTypes = [
      'scene-update', 'starship-update', 'threat-update',
      'round-change', 'vp-change', 'action-log',
      'role-assignment', 'initiative-update', 'turn-change',
    ]
    for (const type of starshipTypes) {
      expect(validateMessageType(type)).toBe(type)
    }
  })

  it('rejects invalid message types', () => {
    expect(validateMessageType('execute')).toBeNull()
    expect(validateMessageType('hack')).toBeNull()
    expect(validateMessageType('')).toBeNull()
  })

  it('rejects non-strings', () => {
    expect(validateMessageType(123)).toBeNull()
    expect(validateMessageType(null)).toBeNull()
  })
})

// ============== validateEffectPayload ==============
describe('validateEffectPayload', () => {
  it('accepts valid effect payloads', () => {
    const result = validateEffectPayload({
      nodeId: 'node-1',
      effectType: 'spark',
    })
    expect(result.valid).toBe(true)
  })

  it('sanitizes nodeId in effects', () => {
    const result = validateEffectPayload({ nodeId: '../escape' })
    expect(result.valid).toBe(false)
  })

  it('rejects non-objects', () => {
    expect(validateEffectPayload(null).valid).toBe(false)
    expect(validateEffectPayload('string').valid).toBe(false)
  })
})

// ============== Security-focused tests ==============
describe('Security: XSS Prevention', () => {
  it('escapes all common XSS vectors in sanitizeString', () => {
    const vectors = [
      '<script>alert(1)</script>',
      '<img src=x onerror=alert(1)>',
      '<svg onload=alert(1)>',
      'javascript:alert(1)',
      '<a href="javascript:alert(1)">click</a>',
      '"><script>alert(1)</script>',
      "'-alert(1)-'",
    ]

    for (const vector of vectors) {
      const sanitized = sanitizeString(vector)
      expect(sanitized).not.toContain('<script')
      expect(sanitized).not.toContain('<img')
      expect(sanitized).not.toContain('<svg')
      expect(sanitized).not.toContain('<a')
    }
  })
})

describe('Security: Injection Prevention', () => {
  it('rejects path traversal in IDs', () => {
    expect(sanitizeId('../../etc/passwd')).toBeNull()
    expect(sanitizeId('..\\..\\windows')).toBeNull()
  })

  it('rejects null bytes in strings', () => {
    const result = sanitizeString('hello\x00world')
    expect(result).toBe('helloworld')
  })
})

describe('Security: DoS Prevention', () => {
  it('truncates oversized strings', () => {
    const megaString = 'x'.repeat(1_000_000)
    const result = sanitizeString(megaString)
    expect(result?.length).toBeLessThanOrEqual(LIMITS.MAX_STRING_LENGTH)
  })

  it('limits access point count', () => {
    const manyPoints = Array(100).fill({
      id: 'ap-1',
      name: 'Test',
      type: 'physical',
      state: 'locked',
      position: { x: 0, y: 0 },
      connectedTo: [],
    })

    const result = validateComputer({
      id: 'comp-1',
      name: 'Test',
      level: 5,
      type: 'tech',
      accessPoints: manyPoints,
    })

    expect(result.valid).toBe(false)
    if (!result.valid) {
      expect(result.error).toContain('Too many access points')
    }
  })
})
