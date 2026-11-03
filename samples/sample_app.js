// Sample front-end JS, as if discovered during a crawl. Used to demonstrate
// `generate-candidates` without a live target. Endpoints are relative to the
// in-scope mock host (http://127.0.0.1:8000/).
const API = {
  search(term) {
    return fetch(`/xss?q=${encodeURIComponent(term)}`).then(r => r.text());
  },
  getItem(id) {
    return fetch(`/item?id=${id}`).then(r => r.json());
  },
  getOrder(order_id) {
    // order_id looks like a sequential object identifier -> possible IDOR
    return fetch(`/api/orders/${order_id}`, { credentials: "include" })
      .then(r => r.json());
  },
};
