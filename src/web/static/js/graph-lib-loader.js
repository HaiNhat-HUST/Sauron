// Lazy-load vis-network from CDN once, on first use of the graph panel.
// Kept out of the initial bundle so the app shell stays light until a user
// actually opens an article graph. The standalone UMD bundle exposes a global
// `vis` namespace (vis.Network, vis.DataSet); the CSS styles tooltips and the
// navigation/zoom controls.

const JS_CDN = "https://cdn.jsdelivr.net/npm/vis-network@9.1.9/standalone/umd/vis-network.min.js";
const CSS_CDN = "https://cdn.jsdelivr.net/npm/vis-network@9.1.9/styles/vis-network.min.css";

let _promise = null;

function ensureCss() {
  if (document.querySelector(`link[data-vis-css]`)) return;
  const link = document.createElement("link");
  link.rel = "stylesheet";
  link.href = CSS_CDN;
  link.setAttribute("data-vis-css", "");
  document.head.appendChild(link);
}

export function loadVisNetwork() {
  if (window.vis?.Network) return Promise.resolve(window.vis);
  if (_promise) return _promise;
  ensureCss();
  _promise = new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = JS_CDN;
    script.async = true;
    script.onload = () =>
      window.vis?.Network ? resolve(window.vis) : reject(new Error("vis-network failed to initialise"));
    script.onerror = () => {
      _promise = null; // allow a retry on the next open
      reject(new Error("Could not load the graph library (network blocked?)"));
    };
    document.head.appendChild(script);
  });
  return _promise;
}
