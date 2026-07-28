/* API client + tiny shared helpers. All /api/* calls go same-origin
   through CloudFront to the Lambda function URL, carrying the Cognito
   ID token; a 401 sends the user back to the login page. */

async function sha256hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function api(path, options = {}) {
  const token = await AUTH.idToken();
  if (!token) { location.href = "/login"; throw new Error("auth"); }
  // x-authorization, not authorization: CloudFront's OAC owns the real
  // Authorization header (SigV4 to the lambda URL) and won't sign if the
  // viewer's could be forwarded. OAC-signed POSTs to a lambda URL also
  // require the viewer to supply the payload hash.
  const headers = { "x-authorization": `Bearer ${token}`, ...(options.headers || {}) };
  if (options.body) headers["x-amz-content-sha256"] = await sha256hex(options.body);
  const resp = await fetch(path, { ...options, headers });
  if (resp.status === 401) {
    // token truly rejected: try one silent refresh before giving up the
    // session — never bounce to login on a server-side 403/5xx, which
    // previously looped users straight back to the sign-in page
    if (!options._retried && await AUTH.idToken()) {
      return api(path, { ...options, _retried: true });
    }
    AUTH.signOut();
    throw new Error("auth");
  }
  if (resp.status === 403) {
    toast("API refused the request (403) — infrastructure issue, not your session");
    throw new Error("forbidden");
  }
  return resp;
}
const apiJson = (p, o) => api(p, o).then(r => r.json());
const apiPost = (p, body) => api(p, {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify(body || {}),
});

/* ---------- helpers ---------- */

function esc(s) { const d = document.createElement("div"); d.textContent = s ?? ""; return d.innerHTML; }
const fmt = (n) => n == null ? "—" : `$${Number(n).toFixed(2)}`;

function timeAgo(iso) {
  if (!iso) return "";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

function svcOf(detector) {
  const d = (detector || "").toLowerCase();
  if (d.startsWith("iam") || d.includes("mfa")) return "IAM";
  if (d.includes("sg") || d.includes("security_group") || d.includes("open")) return "SG";
  if (d.includes("cloudtrail")) return "CT";
  if (d.startsWith("s3")) return "S3";
  if (d.startsWith("ebs") || d.includes("snapshot") || d.includes("volume")) return "EBS";
  if (d.includes("eip")) return "EIP";
  if (d.startsWith("ec2")) return "EC2";
  if (d.startsWith("rds")) return "RDS";
  if (d.includes("elb") || d.includes("load")) return "ELB";
  if (d.includes("eks")) return "EKS";
  if (d.includes("logs") || d.includes("cloudwatch")) return "CW";
  if (d.includes("lambda")) return "LAMBDA";
  if (d.includes("eip")) return "EIP";
  if (d.includes("vpc") || d.includes("nat") || d.includes("network")) return "VPC";
  if (d === "ai" || d.startsWith("ai")) return "AI";
  return "AWS";
}

/* AWS-style vector tile (assets/icons.js) — same signature as before */
function svcIcon(tag, size = 36) {
  return awsIcon(tag, size);
}

function toast(msg, ms = 2600) {
  let el = document.getElementById("toast");
  if (!el) {
    el = document.createElement("div");
    el.id = "toast";
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(el._t);
  el._t = setTimeout(() => el.classList.remove("show"), ms);
}

function download(name, content, type) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([content], { type }));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}
