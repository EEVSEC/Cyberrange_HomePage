// Loopback-only browser fixture. It never sends signup or payment data.
(() => {
  'use strict';
  if (!['localhost', '127.0.0.1', '[::1]'].includes(location.hostname)) return;

  // Loopback has no IP geolocation. Match the pricing page's USD fallback.
  const standard = { region: 'INTL', country: 'US', currency: 'USD', taxable: 2000, gst: 0, total: 2000, payment_methods: ['card'] };
  let checkoutToken;
  let paymentConfirmed = false;

  function quote(code, method) {
    if (!code) return { ...standard };
    return { ...standard, code_error: 'Offer unavailable.' };
  }

  async function request(path, { body, token }) {
    const url = new URL(path, 'https://preview.invalid/');
    if (url.pathname === '/quote') return quote(url.searchParams.get('code'), url.searchParams.get('payment_method'));
    if (path === 'signup' || path === 'login') {
      checkoutToken = crypto.randomUUID();
      return { checkout_token: checkoutToken };
    }
    if (!checkoutToken || (body?.checkout_token || token) !== checkoutToken) {
      throw new Error('Your preview session expired.');
    }
    if (path === 'subscribe') {
      const price = quote(body.code, body.payment_method);
      if (price.code_error) throw Object.assign(new Error(price.code_error), { status: 409 });
      return {
        key_id: 'rzp_test_preview', subscription_id: 'sub_preview',
        payment_method: body.payment_method, currency: price.currency, total: price.total,
        offer_cycles: price.offer_cycles,
      };
    }
    if (path === 'verify' && body.razorpay_subscription_id === 'sub_preview' &&
        body.razorpay_payment_id === 'pay_preview' && body.razorpay_signature === 'local-preview') {
      paymentConfirmed = true;
      return { status: 'active' };
    }
    if (path === 'status') return { status: paymentConfirmed ? 'active' : 'processing' };
    throw new Error('Preview request failed.');
  }

  class Checkout {
    constructor(options) { this.options = options; }
    on() {}
    open() {
      const dialog = document.createElement('dialog');
      dialog.className = 'checkout-panel checkout-preview-modal';
      dialog.setAttribute('aria-label', 'Simulated Razorpay payment');
      dialog.innerHTML = `
        <h2 class="checkout-title">Test payment</h2>
        <p>This simulates Razorpay confirmation for the local preview.</p>
        <button type="button" data-confirm class="btn btn--primary checkout-primary">Simulate successful payment</button>
        <button type="button" data-cancel class="btn btn--ghost checkout-primary">Cancel</button>`;
      let approved = false;
      dialog.querySelector('[data-confirm]').addEventListener('click', () => {
        approved = true;
        dialog.close();
        this.options.handler({
          razorpay_subscription_id: 'sub_preview', razorpay_payment_id: 'pay_preview', razorpay_signature: 'local-preview',
        });
      });
      dialog.querySelector('[data-cancel]').addEventListener('click', () => dialog.close());
      dialog.addEventListener('close', () => {
        dialog.remove();
        if (!approved) this.options.modal.ondismiss();
      });
      document.body.append(dialog);
      dialog.showModal();
    }
  }

  window.crCheckoutPreview = { request, Checkout };
})();
