(function () {
'use strict';
var VERT = `attribute vec2 a_position;
void main() {
  gl_Position = vec4(a_position, 0.0, 1.0);
}`;
var FRAG = `#ifdef GL_FRAGMENT_PRECISION_HIGH
precision highp float;
#else
precision mediump float;
#endif

uniform vec3 u_colors[8];
// Eight packed vectors + eight colour vectors = 16 fragment uniform vectors,
// exactly WebGL1's guaranteed minimum — don't add another. Macros preserve the public u_* API.
uniform vec4 u_scene;      // resolution.xy, time, colour count
uniform vec4 u_shape;      // scale, intensity, paramA, warp
uniform vec4 u_surface;    // detail, contrast, brightness, saturation
uniform vec4 u_finish;     // hue, vignette, blur, grain
uniform vec4 u_transform;  // seed, rotation, drift, OKLab toggle
uniform vec4 u_space;      // offset.xy, pointer.xy
uniform vec4 u_cursor;
uniform vec4 u_hero;       // x: first-viewport height in canvas px (16th vector)

#define u_resolution u_scene.xy
#define u_time u_scene.z
#define u_colorCount u_scene.w
#define u_scale u_shape.x
#define u_intensity u_shape.y
#define u_paramA u_shape.z
#define u_warp u_shape.w
#define u_detail u_surface.x
#define u_contrast u_surface.y
#define u_brightness u_surface.z
#define u_saturation u_surface.w
#define u_hue u_finish.x
#define u_vignette u_finish.y
#define u_blur u_finish.z
#define u_grain u_finish.w
#ifdef GL_FRAGMENT_PRECISION_HIGH
#define u_seed u_transform.x
#else
// Keep hash inputs inside mediump's guaranteed ±2^14 range.
#define u_seed mod(u_transform.x, 31.0)
#endif
#define u_rotate u_transform.y
#define u_drift u_transform.z
#define u_oklab u_transform.w
#define u_offset u_space.xy
#define u_mouse u_space.zw
#define u_cursorPresence u_cursor.x
#define u_cursorEffect u_cursor.y
#define u_cursorStrength u_cursor.z
#define u_cursorRadius u_cursor.w

float hash21(vec2 p) {
#ifndef GL_FRAGMENT_PRECISION_HIGH
  p = mod(p, 31.0);
#endif
  p = fract(p * vec2(234.34, 435.345));
  p += dot(p, p + 34.23);
  return fract(p.x * p.y);
}

// Even, un-structured white noise for film grain (Dave Hoskins hash12). The
// multiply hash above is fine for value noise but shows a faint axis-aligned
// mesh at integer fragment coords, which reads as a net over flat areas.
float grainHash(vec2 p) {
  vec3 p3 = fract(vec3(p.xyx) * 0.1031);
  p3 += dot(p3, p3.yzx + 33.33);
  return fract((p3.x + p3.y) * p3.z);
}

vec2 hash22(vec2 p) {
#ifndef GL_FRAGMENT_PRECISION_HIGH
  p = mod(p, 31.0);
#endif
  float n = sin(dot(p, vec2(41.0, 289.0)));
  return fract(vec2(15731.743, 7892.321) * n);
}

float noise(vec2 p) {
  vec2 i = floor(p);
  vec2 f = fract(p);
  vec2 u = f * f * (3.0 - 2.0 * f);
  return mix(
    mix(hash21(i), hash21(i + vec2(1.0, 0.0)), u.x),
    mix(hash21(i + vec2(0.0, 1.0)), hash21(i + vec2(1.0, 1.0)), u.x),
    u.y);
}

float fbm(vec2 p) {
  float v = 0.0;
  float a = 0.5;
  for (int i = 0; i < 5; i++) {
    v += a * noise(p);
    p = p * 2.03 + vec2(17.0, 9.2);
    a *= 0.5;
  }
  return v;
}

// --- OKLab colour mixing (perceptual), gated by u_oklab -----------------------
vec3 srgbToLinear(vec3 c) {
  return mix(c / 12.92, pow((c + 0.055) / 1.055, vec3(2.4)),
    step(0.04045, c));
}
vec3 linearToSrgb(vec3 c) {
  // max() guards the sRGB branch: out-of-gamut OKLab interpolations can send a
  // channel negative, and pow(negative, …) is NaN which mix()/step() would
  // then propagate. The linear branch clips such channels to 0 downstream.
  return mix(c * 12.92, 1.055 * pow(max(c, vec3(0.0)), vec3(1.0 / 2.4)) - 0.055,
    step(0.0031308, c));
}
vec3 linToOklab(vec3 c) {
  float l = 0.4122214708 * c.r + 0.5363325363 * c.g + 0.0514459929 * c.b;
  float m = 0.2119034982 * c.r + 0.6806995451 * c.g + 0.1073969566 * c.b;
  float s = 0.0883024619 * c.r + 0.2817188376 * c.g + 0.6299787005 * c.b;
  l = pow(max(l, 0.0), 1.0 / 3.0);
  m = pow(max(m, 0.0), 1.0 / 3.0);
  s = pow(max(s, 0.0), 1.0 / 3.0);
  return vec3(
    0.2104542553 * l + 0.7936177850 * m - 0.0040720468 * s,
    1.9779984951 * l - 2.4285922050 * m + 0.4505937099 * s,
    0.0259040371 * l + 0.7827717662 * m - 0.8086757660 * s);
}
vec3 oklabToLin(vec3 c) {
  float l = c.x + 0.3963377774 * c.y + 0.2158037573 * c.z;
  float m = c.x - 0.1055613458 * c.y - 0.0638541728 * c.z;
  float s = c.x - 0.0894841775 * c.y - 1.2914855480 * c.z;
  l = l * l * l; m = m * m * m; s = s * s * s;
  return vec3(
    4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
    -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
    -0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s);
}
vec3 mixColour(vec3 a, vec3 b, float t) {
  if (u_oklab > 0.5) {
    vec3 la = linToOklab(srgbToLinear(a));
    vec3 lb = linToOklab(srgbToLinear(b));
    return clamp(linearToSrgb(oklabToLin(mix(la, lb, t))), 0.0, 1.0);
  }
  return mix(a, b, t);
}

// Mix through the recipe colours; x is clamped to 0..1. WebGL1 forbids
// dynamic uniform indexing in fragment shaders, hence the constant loop.
vec3 palette(float x) {
  float n = max(u_colorCount - 1.0, 1.0);
  float f = clamp(x, 0.0, 1.0) * n;
  vec3 col = u_colors[0];
  for (int i = 0; i < 7; i++) {
    if (float(i) < n)
      col = mixColour(col, u_colors[i + 1],
        smoothstep(0.0, 1.0, clamp(f - float(i), 0.0, 1.0)));
  }
  return col;
}

vec3 hueRotate(vec3 col, float a) {
  const mat3 toYIQ = mat3(0.299, 0.596, 0.211,
                          0.587, -0.274, -0.523,
                          0.114, -0.322, 0.312);
  const mat3 toRGB = mat3(1.0, 1.0, 1.0,
                          0.956, -0.272, -1.106,
                          0.621, -0.647, 1.703);
  vec3 yiq = toYIQ * col;
  float ca = cos(a), sa = sin(a);
  yiq = vec3(yiq.x, yiq.y * ca - yiq.z * sa, yiq.y * sa + yiq.z * ca);
  return toRGB * yiq;
}

float silkField(vec2 p, float t) {
  vec2 q = p * 1.6;
  float amp = 0.25 + u_intensity * 0.85;
  for (float i = 1.0; i < 5.0; i += 1.0) {
    q.x += amp / i * cos(i * 2.4 * q.y + t * 0.8 + u_seed);
    q.y += amp / i * cos(i * 1.7 * q.x + t * 0.6);
  }
  return 0.5 + 0.5 * sin(q.x + q.y);
}

// The field doubles as a height map: lit like draped fabric (shadow in the
// folds, a broad sheen plus a soft glint on the crests), then mixed over
// the flat colour by u_paramA (inside the moving patches) so it only partly
// reads as cloth.
vec3 shade(vec2 uv, vec2 p, float t) {
  float h = silkField(p, t);
  vec3 base = palette(h);
  // A wide sampling step acts as a blur on the slope and height, so creases
  // in the field become broad rounded folds (like draped silk) instead of
  // sharp pointed ridges.
  vec2 e = vec2(0.04, 0.0);
  float hr = silkField(p + e.xy, t), hl = silkField(p - e.xy, t);
  float hu = silkField(p + e.yx, t), hd = silkField(p - e.yx, t);
  float hs = (h * 2.0 + hr + hl + hu + hd) / 6.0;
  vec3 n = normalize(vec3(hl - hr, hd - hu, e.x * 2.0 * 3.0));
  vec3 l = normalize(vec3(-0.45, 0.55, 0.7));
  vec3 hv = normalize(l + vec3(0.0, 0.0, 1.0));
  float diffuse = clamp(dot(n, l), 0.0, 1.0);
  float nh = max(dot(n, hv), 0.0);
  float sheen = pow(nh, 6.0) * 0.3 + pow(nh, 18.0) * 0.14;
  // Light by sliding along the palette rather than tinting: folds sink to
  // the deepest recipe colour, crests rise to the lightest, so the cloth
  // never leaves the original pearl-blue colours (no grey, no blown white).
  // Three of the four recipe colours are near-white, so h is pulled down
  // toward the blue-grey end; otherwise the patch reads as mostly white.
  vec3 cloth = palette(hs * 0.75 - 0.1 + (diffuse - 0.8) * 1.6 + sheen * 0.4);
  // One large cloth patch orbits inside the first viewport (measured from
  // the canvas top, so it's in the hero from the first frame); the rest of
  // the field stays flat silk. Noise wobbles its edge so it isn't a circle.
  vec2 fc = vec2(gl_FragCoord.x, u_resolution.y - gl_FragCoord.y);
  vec2 box = vec2(u_resolution.x, max(u_hero.x, 1.0));
  vec2 centre = box * vec2(0.5 + 0.24 * cos(t * 0.5), 0.45 + 0.16 * sin(t * 0.5));
  float d = length((fc - centre) / box) + (noise(p * 1.4 + t * 0.2) - 0.5) * 0.18;
  float clothMask = 1.0 - smoothstep(0.1, 0.7, d);
  return mix(base, cloth, u_paramA * clothMask);
}

void main() {
  vec2 uv = gl_FragCoord.xy / u_resolution.xy;
  vec2 screenUv = uv;
  // Anchor the field on the hero (first viewport), not the middle of this
  // ~3-viewport-tall canvas, and scale it by the hero's short side. Centring
  // on the canvas made the hero sample a different, whiter, 2x-zoomed part of
  // the silk on wide screens. +1.3 picks the band that reads best there.
  float heroH = max(u_hero.x, 1.0);
  vec2 p = (gl_FragCoord.xy
    - vec2(0.5 * u_resolution.x, u_resolution.y - 0.5 * heroH))
    / min(u_resolution.x, heroH) + vec2(0.0, 1.3);
  float cursorMask = 0.0;

  // Cursor modes 1–3 are local distortions. Push shifts the same screen-space
  // coordinates before field transforms, so Zoom/Rotate don't change its feel.
  if (u_cursorPresence > 0.001) {
    // u_mouse is normalized to -1..1 in canvas space. Convert it to the same
    // aspect-corrected screen space as p so effects stay under the cursor.
    vec2 cursor = (0.5 * u_mouse * u_resolution.xy)
      / min(u_resolution.x, u_resolution.y);
    vec2 cursorDelta = p - cursor;
    if (u_cursorEffect < 0.5) {
      p += cursor * u_cursorPresence * u_cursorStrength * 0.55;
    } else {
      float cursorDistance = length(cursorDelta);
      vec2 cursorDirection = cursorDelta / max(cursorDistance, 0.0001);
      cursorMask = u_cursorPresence
        * (1.0 - smoothstep(0.0, u_cursorRadius, cursorDistance));
      if (u_cursorEffect < 1.5) {
        p -= cursorDirection * cursorMask * u_cursorStrength * 0.24;
      } else if (u_cursorEffect < 2.5) {
        float cursorAngle = cursorMask * u_cursorStrength * 2.2;
        float cc = cos(cursorAngle), cs = sin(cursorAngle);
        p = cursor + mat2(cc, -cs, cs, cc) * cursorDelta;
      } else if (u_cursorEffect < 3.5) {
        float ripple = sin(
          cursorDistance / max(u_cursorRadius, 0.001) * 18.0 - u_time * 5.0);
        p -= cursorDirection * ripple * cursorMask * u_cursorStrength * 0.07;
      }
    }
  }

  // Keep presets that read uv (rather than p) in the same warped space.
  uv = p * min(u_resolution.x, u_resolution.y) / u_resolution.xy + 0.5;
  p *= u_scale;
  // Field transform: rotate, pan, pointer push, slow drift.
  if (abs(u_rotate) > 0.0001) {
    float cr = cos(u_rotate), sr = sin(u_rotate);
    p = mat2(cr, -sr, sr, cr) * p;
  }
  p += u_offset;
  if (u_drift > 0.0001)
    p += u_drift * vec2(sin(u_time * 0.31), cos(u_time * 0.23));
  // Organic domain warp.
  if (u_warp > 0.0) {
    p += u_warp * (vec2(
      fbm(p * u_detail + u_seed),
      fbm(p * u_detail + vec2(5.2, 1.3))) - 0.5);
  }
  // Shade, with an optional soft 5-tap blur.
  vec3 col;
  if (u_blur > 0.0) {
    float e = u_blur;
    float pe = e * u_scale;
    vec2 uvE = vec2(e) * min(u_resolution.x, u_resolution.y) / u_resolution.xy;
    col  = shade(uv, p, u_time) * 0.36;
    col += shade(uv + vec2(uvE.x, 0.0), p + vec2(pe, 0.0), u_time) * 0.16;
    col += shade(uv - vec2(uvE.x, 0.0), p - vec2(pe, 0.0), u_time) * 0.16;
    col += shade(uv + vec2(0.0, uvE.y), p + vec2(0.0, pe), u_time) * 0.16;
    col += shade(uv - vec2(0.0, uvE.y), p - vec2(0.0, pe), u_time) * 0.16;
  } else {
    col = shade(uv, p, u_time);
  }
  // Post: contrast, saturation, hue, brightness, vignette, grain.
  if (abs(u_contrast - 1.0) > 0.0001)
    col = (col - 0.5) * u_contrast + 0.5;
  if (abs(u_saturation - 1.0) > 0.0001) {
    float luma = dot(col, vec3(0.299, 0.587, 0.114));
    col = mix(vec3(luma), col, u_saturation);
  }
  if (abs(u_hue) > 0.0001)
    col = hueRotate(col, u_hue);
  if (abs(u_brightness) > 0.0001)
    col += u_brightness;
  if (u_vignette > 0.0001) {
    float vd = length(screenUv - 0.5) * 1.41421356;
    col *= 1.0 - u_vignette * smoothstep(0.35, 1.0, vd);
  }
  if (u_cursorPresence > 0.001 && u_cursorEffect > 3.5)
    col += (vec3(0.18) + col * 0.12) * cursorMask * u_cursorStrength;
  if (u_grain > 0.0001)
    col += (grainHash(
      gl_FragCoord.xy + vec2(u_seed * 17.0, u_seed * 31.0)) - 0.5) * u_grain;
  gl_FragColor = vec4(clamp(col, 0.0, 1.0), 1.0);
}
`;
/* EEVSEC "Pearl Silver" silk background.
 * The GLSL above is copied unchanged from the brand kit (background/silk-shader.tsx,
 * credited there to the 21st.dev Shader Builder); only this dependency-free
 * driver is new. */
var host = document.querySelector('.field');
if (host) {
  var PEARL = ['#CBD4DB', '#E5EAF0', '#F8FAFC', '#FFFFFF'];
  var U = {
    colorCount: 4, scale: 1.26, intensity: 0.28, paramA: 0.78, warp: 0,
    detail: 2.4, contrast: 1.113, brightness: -0.07, saturation: 1.2,
    hue: 0, vignette: 0, blur: 0, grain: 0.007, seed: 1581, rotate: 0,
    offsetX: 0, offsetY: 0, drift: 0, cursorEffect: 2, cursorStrength: 0.65,
    cursorRadius: 0.46, oklab: 0, timeScale: 0.18
  };

  var canvas = document.createElement('canvas');
  canvas.className = 'field__silk';
  canvas.setAttribute('aria-hidden', 'true');
  host.appendChild(canvas);

  var gl = canvas.getContext('webgl', { antialias: false });
  if (gl) {
    var compile = function (type, code) {
      var sh = gl.createShader(type);
      gl.shaderSource(sh, code);
      gl.compileShader(sh);
      return sh;
    };
    var prog = gl.createProgram();
    var vs = compile(gl.VERTEX_SHADER, VERT);
    var fs = compile(gl.FRAGMENT_SHADER, FRAG);
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
      canvas.remove(); /* the CSS pearl gradient on .field stays visible */
    } else {
      gl.deleteShader(vs); gl.deleteShader(fs);
      gl.useProgram(prog);

      var buf = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, buf);
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
      var loc = gl.getAttribLocation(prog, 'a_position');
      gl.enableVertexAttribArray(loc);
      gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);

      var u = {};
      ['colors', 'scene', 'shape', 'surface', 'finish', 'transform', 'space', 'cursor', 'hero']
        .forEach(function (n) { u[n] = gl.getUniformLocation(prog, 'u_' + n); });

      var colors = [];
      PEARL.forEach(function (hex) {
        [1, 3, 5].forEach(function (i) { colors.push(parseInt(hex.slice(i, i + 2), 16) / 255); });
      });
      gl.uniform3fv(u.colors, new Float32Array(colors));
      gl.uniform4f(u.shape, U.scale, U.intensity, U.paramA, U.warp);
      gl.uniform4f(u.surface, U.detail, U.contrast, U.brightness, U.saturation);
      gl.uniform4f(u.finish, U.hue, U.vignette, U.blur, U.grain);
      gl.uniform4f(u.transform, U.seed, U.rotate, U.drift, U.oklab);
      gl.uniform4f(u.cursor, 0, U.cursorEffect, U.cursorStrength, U.cursorRadius);
      gl.uniform4f(u.space, U.offsetX, U.offsetY, 0, 0);

      var motion = window.matchMedia('(prefers-reduced-motion: reduce)');
      var raf = 0, visible = document.visibilityState === 'visible', inView = true;
      var bounds = canvas.getBoundingClientRect();
      var t0 = performance.now();

      var resize = function () {
        bounds = canvas.getBoundingClientRect();
        /* 1x CSS pixels, capped near 6M px: soft silk gains nothing from retina density */
        var w = Math.max(1, Math.round(bounds.width));
        var h = Math.max(1, Math.round(bounds.height));
        var k = Math.min(1, Math.sqrt(6e6 / Math.max(1, w * h)));
        w = Math.max(1, Math.round(w * k));
        h = Math.max(1, Math.round(h * k));
        if (canvas.width !== w || canvas.height !== h) {
          canvas.width = w; canvas.height = h;
          gl.viewport(0, 0, w, h);
        }
      };

      var request = function () {
        if (!raf && visible && inView) raf = requestAnimationFrame(render);
      };
      var render = function (now) {
        raf = 0;
        if (!visible || !inView) return;
        resize();
        var t = motion.matches ? 0 : ((now - t0) / 1000) * U.timeScale;
        gl.uniform4f(u.scene, canvas.width, canvas.height, t, U.colorCount);
        gl.uniform4f(u.hero,
          Math.min(window.innerHeight, bounds.height) * (canvas.height / Math.max(bounds.height, 1)),
          0, 0, 0);
        gl.drawArrays(gl.TRIANGLES, 0, 3);
        if (!motion.matches) request();
      };

      new ResizeObserver(request).observe(canvas);
      new IntersectionObserver(function (e) {
        inView = e[0] ? e[0].isIntersecting : true;
        if (inView) request(); else if (raf) { cancelAnimationFrame(raf); raf = 0; }
      }).observe(canvas);
      document.addEventListener('visibilitychange', function () {
        visible = document.visibilityState === 'visible';
        if (visible) request(); else if (raf) { cancelAnimationFrame(raf); raf = 0; }
      });
      motion.addEventListener('change', request);
      request();
    }
  }
}
})();
