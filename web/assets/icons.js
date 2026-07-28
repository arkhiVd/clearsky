/* AWS-architecture-style service icons — self-contained vector glyphs on
   official AWS category colours (compute orange, storage green, database
   blue, networking purple, app-integration pink, security red), ported
   from the architecture generator's icon set. awsIcon(tag, size) returns
   a rounded tile with a white glyph, like the official icon sheets. */

const AWS_CAT = {
  compute:  "#ED7100",
  storage:  "#7AA116",
  database: "#2E27AD",
  network:  "#8C4FFF",
  appint:   "#E7157B",
  security: "#DD344C",
  ai:       "#7d55d4",
  generic:  "#5A6B86",
};

/* tag -> [category, [svg fragments in a 48x48 box]] */
const AWS_GLYPHS = {
  EC2: ["compute", [
    '<rect x="12" y="12" width="24" height="24" rx="2" fill="none" stroke="#fff" stroke-width="2.6"/>',
    '<rect x="18" y="18" width="12" height="12" rx="1" fill="#fff"/>',
    '<path d="M17 5v5M24 5v5M31 5v5M17 38v5M24 38v5M31 38v5M5 17h5M5 24h5M5 31h5M38 17h5M38 24h5M38 31h5" stroke="#fff" stroke-width="2.6"/>',
  ]],
  LAMBDA: ["compute", [
    '<path d="M12 8h9l13.5 28.5 5-10.5h6.5v3.5L38 43h-7L21.5 22 13 40H7l12-25-5-10.5z" fill="#fff"/>',
  ]],
  EKS: ["compute", [
    '<path d="M24 5l16 9v18l-16 9-16-9V14z" fill="none" stroke="#fff" stroke-width="2.6"/>',
    '<path d="M24 14v20M15 19l18 10M33 19L15 29" stroke="#fff" stroke-width="2.2"/>',
  ]],
  S3: ["storage", [
    '<path d="M9 13c0-3.9 6.7-7 15-7s15 3.1 15 7l-3.4 24.5c-.4 3.1-5.4 5.5-11.6 5.5s-11.2-2.4-11.6-5.5z" fill="#fff"/>',
    '<ellipse cx="24" cy="13" rx="15" ry="7" fill="none" stroke="__BG__" stroke-width="2.4"/>',
  ]],
  EBS: ["storage", [
    '<rect x="8" y="12" width="32" height="10" rx="3" fill="#fff"/>',
    '<rect x="8" y="26" width="32" height="10" rx="3" fill="#fff"/>',
    '<circle cx="14" cy="17" r="2" fill="__BG__"/><circle cx="14" cy="31" r="2" fill="__BG__"/>',
  ]],
  DDB: ["database", [
    '<path d="M10 11c0-3.3 6.3-6 14-6s14 2.7 14 6v26c0 3.3-6.3 6-14 6s-14-2.7-14-6z" fill="#fff"/>',
    '<path d="M10 19c3 2.5 8 4 14 4s11-1.5 14-4M10 29c3 2.5 8 4 14 4s11-1.5 14-4" fill="none" stroke="__BG__" stroke-width="2.4"/>',
  ]],
  RDS: ["database", [
    '<path d="M10 11c0-3.3 6.3-6 14-6s14 2.7 14 6v26c0 3.3-6.3 6-14 6s-14-2.7-14-6z" fill="#fff"/>',
    '<path d="M10 13c3 2.7 8 4.2 14 4.2S35 15.7 38 13" fill="none" stroke="__BG__" stroke-width="2.4"/>',
  ]],
  ELB: ["network", [
    '<circle cx="12" cy="24" r="7" fill="#fff"/>',
    '<circle cx="38" cy="10" r="5" fill="#fff"/><circle cx="38" cy="24" r="5" fill="#fff"/><circle cx="38" cy="38" r="5" fill="#fff"/>',
    '<path d="M18 21 33 11M19 24h14M18 27l15 10" fill="none" stroke="#fff" stroke-width="2.4"/>',
  ]],
  VPC: ["network", [
    '<path d="M24 6l16 8-16 8-16-8 16-8z" fill="#fff"/>',
    '<path d="M8 22l16 8 16-8M8 30l16 8 16-8" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>',
  ]],
  EIP: ["network", [
    '<circle cx="24" cy="24" r="12" fill="none" stroke="#fff" stroke-width="2.6"/>',
    '<path d="M4 24h8M36 24h8" stroke="#fff" stroke-width="2.6"/>',
    '<circle cx="24" cy="24" r="5" fill="#fff"/>',
  ]],
  APIGW: ["appint", [
    '<path d="M15 10 5 24l10 14h6L11 24 21 10zM33 10l10 14-10 14h-6l10-14L27 10z" fill="#fff"/>',
    '<rect x="21.5" y="21" width="5" height="6" rx="1" fill="#fff"/>',
  ]],
  CW: ["appint", [
    '<circle cx="24" cy="26" r="15" fill="none" stroke="#fff" stroke-width="2.6"/>',
    '<path d="M24 16v10l7 5" fill="none" stroke="#fff" stroke-width="2.6" stroke-linecap="round"/>',
    '<path d="M14 6l-7 6M34 6l7 6" stroke="#fff" stroke-width="2.6" stroke-linecap="round"/>',
  ]],
  CT: ["appint", [
    '<path d="M12 6h20l6 6v30H12z" fill="#fff"/>',
    '<path d="M18 20h14M18 26h14M18 32h9" stroke="__BG__" stroke-width="2.4" stroke-linecap="round"/>',
  ]],
  IAM: ["security", [
    '<circle cx="24" cy="15" r="8" fill="#fff"/>',
    '<path d="M8 42c0-9 7-15 16-15s16 6 16 15z" fill="#fff"/>',
  ]],
  SG: ["security", [
    '<path d="M24 4l16 6v12c0 10-6.6 17.4-16 22-9.4-4.6-16-12-16-22V10z" fill="#fff"/>',
    '<path d="M17 23l5 5 9-10" fill="none" stroke="__BG__" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>',
  ]],
  AI: ["ai", [
    '<path d="M24 6v5M24 37v5M8.5 10.5l3.5 3.5M36 34l3.5 3.5M6 24h5M37 24h5M8.5 37.5L12 34M36 14l3.5-3.5" stroke="#fff" stroke-width="2.6" stroke-linecap="round"/>',
    '<circle cx="24" cy="24" r="7" fill="#fff"/>',
  ]],
  AWS: ["generic", [
    '<rect x="9" y="9" width="30" height="30" rx="4" fill="none" stroke="#fff" stroke-width="2.6"/>',
    '<path d="M9 19h30M19 9v30" stroke="#fff" stroke-width="2.2"/>',
  ]],
};
AWS_GLYPHS.LOGS = AWS_GLYPHS.CW;
AWS_GLYPHS.SNS = AWS_GLYPHS.APIGW;

function awsIcon(tag, size = 36) {
  const [cat, glyph] = AWS_GLYPHS[tag] || AWS_GLYPHS.AWS;
  const bg = AWS_CAT[cat];
  const body = glyph.join("").replaceAll("__BG__", bg);
  return `<svg class="svcicon" width="${size}" height="${size}" viewBox="0 0 48 48"
    style="border-radius:${Math.round(size * 0.22)}px;background:linear-gradient(160deg,${bg},${shade(bg, -18)});flex-shrink:0"
    role="img" aria-label="${tag}"><g transform="translate(4.8,4.8) scale(0.8)">${body}</g></svg>`;
}

function shade(hex, pct) {
  const n = parseInt(hex.slice(1), 16);
  const f = (c) => Math.max(0, Math.min(255, Math.round(c * (1 + pct / 100))));
  const r = f(n >> 16), g = f((n >> 8) & 255), b = f(n & 255);
  return `#${((r << 16) | (g << 8) | b).toString(16).padStart(6, "0")}`;
}
