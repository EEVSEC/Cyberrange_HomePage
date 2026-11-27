(() => {
  'use strict';

  const byId = id => document.getElementById(id);
  const arena = 'https://cyberrange.eevsec.com';
  const preview = ['localhost', '127.0.0.1', '[::1]'].includes(location.hostname)
    ? window.crCheckoutPreview : null;
  const accountForm = byId('account-form');
  const fields = accountForm.elements;
  const confirmPassword = byId('confirm-password');
  const passwordInputs = [fields.password, confirmPassword];
  const passwordToggles = accountForm.querySelectorAll('.checkout-password button');
  const passwordMismatch = byId('password-mismatch');
  const passwordLengthError = byId('password-length-error');
  const capsLock = byId('password-caps-lock');
  const maxPasswordLength = 1024;
  const minNewPasswordLength = 15;
  const phoneFields = byId('phone-fields');
  const phone = window.crCheckoutPhone;
  const accountStatus = byId('account-status');
  const coupon = byId('coupon');
  const pay = byId('pay');
  const paymentStatus = byId('payment-status');
  const checkPayment = byId('check-payment');
  const methods = byId('payment-methods');
  const methodNames = { card: 'Credit or debit card', upi: 'UPI AutoPay', emandate: 'Bank eMandate' };
  const countries = window.crCheckoutCountries || {};
  const indiaStates = {
    '01': 'Jammu and Kashmir', '02': 'Himachal Pradesh', '03': 'Punjab', '04': 'Chandigarh',
    '05': 'Uttarakhand', '06': 'Haryana', '07': 'Delhi', '08': 'Rajasthan', '09': 'Uttar Pradesh',
    '10': 'Bihar', '11': 'Sikkim', '12': 'Arunachal Pradesh', '13': 'Nagaland', '14': 'Manipur',
    '15': 'Mizoram', '16': 'Tripura', '17': 'Meghalaya', '18': 'Assam', '19': 'West Bengal',
    '20': 'Jharkhand', '21': 'Odisha', '22': 'Chhattisgarh', '23': 'Madhya Pradesh', '24': 'Gujarat',
    '26': 'Dadra and Nagar Haveli and Daman and Diu', '27': 'Maharashtra', '29': 'Karnataka',
    '30': 'Goa', '31': 'Lakshadweep', '32': 'Kerala', '33': 'Tamil Nadu', '34': 'Puducherry',
    '35': 'Andaman and Nicobar Islands', '36': 'Telangana', '37': 'Andhra Pradesh', '38': 'Ladakh',
  };

  let mode = 'signup';
  let standardQuote;
  let quote;
  let checkoutToken;
  let quotedCode = '';
  let paymentBusy = false;
  let quoteBusy = false;
  let verifying = false;
  let razorpayScript;

  const countriesByName = Object.entries(countries).sort(([, a], [, b]) => a[0].localeCompare(b[0]));
  for (const [code, [name]] of countriesByName) {
    fields.country.add(new Option(name, code));
  }
  fields.country.addEventListener('change', updateBillingState);

  function updateBillingState() {
    const country = fields.country.value;
    const india = country === 'IN';
    const regions = india
      ? Object.entries(indiaStates).map(([code, name]) => [name, code])
      : countries[country]?.[1] || [];
    const hasRegions = regions.length > 0;
    byId('billing-state-row').hidden = !hasRegions;
    byId('billing-state-label').textContent = india ? 'State or union territory' : 'State, province or region';
    fields.billing_state.disabled = !hasRegions;
    fields.billing_state.required = hasRegions;
    fields.billing_state.replaceChildren(
      new Option(india ? 'Select your state or territory' : 'Select your region', ''),
      ...[...regions].sort(([a], [b]) => a.localeCompare(b)).map(([name, code]) => new Option(name, code)),
    );
  }

  function setPasswordVisibility(button, input, visible) {
    input.type = visible ? 'text' : 'password';
    const action = visible ? 'Hide' : 'Show';
    button.toggleAttribute('data-visible', visible);
    button.setAttribute('aria-label', action + (input === confirmPassword ? ' password confirmation' : ' password'));
  }

  function showPasswordMismatch(mismatch) {
    const message = mismatch ? 'Passwords do not match.' : '';
    if (passwordMismatch.textContent !== message) passwordMismatch.textContent = message;
    for (const input of passwordInputs) {
      if (mismatch) input.setAttribute('aria-invalid', 'true');
      else input.removeAttribute('aria-invalid');
    }
  }

  function passwordsMatch() {
    const mismatch = mode === 'signup' && confirmPassword.value !== '' &&
      fields.password.value.normalize('NFC') !== confirmPassword.value.normalize('NFC');
    showPasswordMismatch(mismatch);
    return !mismatch;
  }

  function resetPasswordControls() {
    capsLock.textContent = '';
    passwordLengthError.textContent = '';
    showPasswordMismatch(false);
    for (const button of passwordToggles) {
      setPasswordVisibility(button, byId(button.getAttribute('aria-controls')), false);
    }
  }

  for (const button of passwordToggles) {
    const input = byId(button.getAttribute('aria-controls'));
    button.addEventListener('click', () => setPasswordVisibility(button, input, input.type === 'password'));
  }
  for (const input of passwordInputs) {
    input.addEventListener('input', () => {
      if (input === fields.password) passwordLengthError.textContent = '';
      passwordsMatch();
    });
    input.addEventListener('change', passwordsMatch);
    const reportCapsLock = event => {
      const message = event.getModifierState('CapsLock') ? 'Caps Lock is on.' : '';
      if (capsLock.textContent !== message) capsLock.textContent = message;
    };
    input.addEventListener('keydown', reportCapsLock);
    input.addEventListener('keyup', reportCapsLock);
    input.addEventListener('blur', () => { capsLock.textContent = ''; });
  }
  accountForm.addEventListener('reset', resetPasswordControls);

  function feedback(element, message, error = false) {
    element.textContent = message;
    element.dataset.error = String(error);
  }

  async function request(path, { body, token } = {}) {
    if (preview) return preview.request(path, { body, token });

    let response;
    try {
      response = await fetch(new URL('/api/billing/' + path, arena), {
        method: body ? 'POST' : 'GET',
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
        signal: AbortSignal.timeout(15000),
        headers: {
          Accept: 'application/json',
          ...(body ? { 'Content-Type': 'application/json' } : {}),
          ...(token ? { 'X-Checkout-Token': token } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch {
      throw new Error('Checkout could not connect. Please try again.');
    }
    if (!response.ok) {
      const messages = {
        401: path === 'login' ? 'Incorrect email or password.' : 'Your checkout session expired. Sign in to continue.',
        409: 'The account or checkout details have changed.',
        429: 'Too many attempts. Wait a moment and try again.',
        503: 'Checkout is currently unavailable. Contact hi@eevsec.com for help.',
      };
      throw Object.assign(new Error(messages[response.status] || 'Checkout could not continue. Check your details or try again.'), { status: response.status });
    }
    const data = await response.json();
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Checkout returned an unexpected response.');
    return data;
  }

  function minorAmount(value) {
    return Number.isSafeInteger(value) && value >= 0;
  }

  async function getQuote(code = '', method = '') {
    const params = new URLSearchParams();
    if (code) params.set('code', code);
    if (method) params.set('payment_method', method);
    const data = await request('quote' + (params.size ? '?' + params : ''), { token: checkoutToken });
    if (!['INR', 'USD'].includes(data.currency) || !['IN', 'INTL'].includes(data.region) ||
        (data.region === 'IN') !== (data.currency === 'INR') ||
        ![data.taxable, data.gst, data.total].every(minorAmount) ||
        data.total <= 0 || data.taxable + data.gst !== data.total ||
        !Array.isArray(data.payment_methods) || !data.payment_methods.length ||
        data.payment_methods.some(value => !Object.hasOwn(methodNames, value)) ||
        (method && !data.payment_methods.includes(method))) {
      throw new Error('Checkout could not verify the total or payment method.');
    }
    return data;
  }

  function switchAccount(nextMode) {
    mode = nextMode;
    const signup = mode === 'signup';
    byId('choose-signup').setAttribute('aria-pressed', String(signup));
    byId('choose-login').setAttribute('aria-pressed', String(!signup));
    byId('account-title').textContent = signup ? 'Create your account' : 'Sign in to CyberRange';
    byId('account-intro').hidden = signup;
    byId('account-submit').textContent = signup ? 'Create account' : 'Sign in and continue';
    fields.email.autocomplete = signup ? 'email' : 'username';
    byId('full-name-row').hidden = !signup;
    fields.full_name.disabled = !signup;
    phoneFields.hidden = !signup;
    phoneFields.disabled = !signup;
    phone?.clearError();
    fields.password.autocomplete = signup ? 'new-password' : 'current-password';
    byId('password-requirements').hidden = !signup;
    if (signup) fields.password.setAttribute('passwordrules', 'minlength: 15; maxlength: 1024;');
    else fields.password.removeAttribute('passwordrules');
    const descriptions = 'password-length-error password-mismatch password-caps-lock';
    fields.password.setAttribute('aria-describedby', signup ? 'password-requirements ' + descriptions : descriptions);
    fields.password.value = '';
    confirmPassword.value = '';
    resetPasswordControls();
    confirmPassword.disabled = !signup;
    byId('confirm-password-row').hidden = !signup;
    const billingFields = byId('billing-fields');
    billingFields.hidden = !signup;
    billingFields.disabled = !signup;
  }

  function activeStep(name) {
    for (const step of ['account', 'payment', 'complete']) byId(step + '-step').hidden = step !== name;
    for (const step of ['account', 'payment']) {
      const element = byId('checkout-step-' + step);
      if (step === name) element.setAttribute('aria-current', 'step');
      else element.removeAttribute('aria-current');
    }
    byId(name + '-title').focus();
  }

  function complete(alreadySubscribed = false) {
    checkoutToken = undefined;
    byId('complete-title').textContent = alreadySubscribed ? 'Your subscription is active' : 'Payment confirmed';
    if (preview) {
      byId('complete-message').textContent = 'The preview payment was confirmed. No real account or payment was created.';
      byId('enter-arena').hidden = true;
    }
    activeStep('complete');
  }

  function setAccountBusy(busy) {
    byId('account-fields').disabled = busy;
    byId('choose-signup').disabled = busy;
    byId('choose-login').disabled = busy;
  }

  for (const action of ['signup', 'login']) byId('choose-' + action).addEventListener('click', () => {
    switchAccount(action);
    if (standardQuote) feedback(accountStatus, '');
  });

  accountForm.addEventListener('submit', async event => {
    event.preventDefault();
    if (!standardQuote || byId('account-fields').disabled) return;
    const action = mode;
    const passwordValue = fields.password.value;
    const passwordLength = passwordValue.length <= 2 * maxPasswordLength ? [...passwordValue].length : Infinity;
    if (passwordLength > maxPasswordLength ||
        (action === 'signup' && [...passwordValue.normalize('NFC')].length < minNewPasswordLength)) {
      passwordLengthError.textContent = action === 'signup'
        ? `Use ${minNewPasswordLength} to ${maxPasswordLength} characters for your password.`
        : `Use up to ${maxPasswordLength} characters for your password.`;
      fields.password.setAttribute('aria-invalid', 'true');
      fields.password.focus();
      return;
    }
    if (!passwordsMatch()) {
      confirmPassword.focus();
      return;
    }
    const body = { email: fields.email.value.trim(), password: passwordValue };
    if (action === 'signup') {
      body.full_name = fields.full_name.value.trim();
      if (!body.full_name) {
        feedback(accountStatus, 'Enter your full name.', true);
        fields.full_name.focus();
        return;
      }
      body.country = fields.country.value;
      if (!fields.billing_state.disabled) body.billing_state = fields.billing_state.value;
      const normalizedPhone = phone.signupValue();
      if (!normalizedPhone) return;
      // The billing API must validate this again before storing it.
      body.phone_number = normalizedPhone;
    }

    setAccountBusy(true);
    feedback(accountStatus, action === 'signup' ? 'Creating your account…' : 'Signing in…');
    try {
      if (!preview) {
        try {
          body.captcha_token = await window.crRecaptcha.execute();
          if (!body.captcha_token) throw new Error();
        } catch {
          throw new Error('Verification was unavailable. Please try again.');
        }
      }
      const result = await request(action, { body });
      if (action === 'login' && result.status === 'already_subscribed') {
        accountForm.reset();
        complete(true);
      } else {
        if (typeof result.checkout_token !== 'string' || !result.checkout_token) {
          throw new Error('Checkout could not start. Please try signing in.');
        }
        checkoutToken = result.checkout_token;
        accountForm.reset();
        showMethods(standardQuote.payment_methods);
        activeStep('payment');
        await refreshQuote('');
      }
    } catch (error) {
      if (action === 'login' && error.status === 401) {
        fields.password.value = '';
        resetPasswordControls();
      }
      const message = action === 'signup' && error.status === 409
        ? 'Could not create an account. Check your details or try signing in.'
        : error.message;
      feedback(accountStatus, message, true);
    } finally {
      setAccountBusy(false);
      if (accountStatus.dataset.error === 'true') accountStatus.focus();
    }
  });

  function showMethods(available) {
    methods.replaceChildren(...[...new Set(available)].map((value, index) => {
      const label = document.createElement('label');
      const radio = document.createElement('input');
      radio.type = 'radio';
      radio.name = 'payment_method';
      radio.value = value;
      radio.checked = index === 0;
      label.append(radio, methodNames[value]);
      return label;
    }));
  }

  const selectedMethod = () => methods.querySelector(':checked')?.value || '';
  const typedCode = () => coupon.value.trim().toUpperCase();
  const money = (amount, currency) => new Intl.NumberFormat(currency === 'INR' ? 'en-IN' : 'en-US', {
    style: 'currency', currency,
  }).format(amount / 100);

  function setPaymentControls() {
    const busy = quoteBusy || paymentBusy || verifying;
    byId('coupon-fields').disabled = busy;
    byId('method-fields').disabled = busy;
    pay.disabled = busy || !quote || quotedCode !== typedCode();
  }

  async function refreshQuote(code) {
    if (quoteBusy || paymentBusy || verifying) return;
    quoteBusy = true;
    quotedCode = code;
    quote = undefined;
    setPaymentControls();
    byId('payment-summary').hidden = true;
    byId('payment-renewal').textContent = '';
    feedback(paymentStatus, 'Checking your total…');
    try {
      const method = selectedMethod();
      const result = await getQuote(code, method);
      if (result.currency !== standardQuote.currency) throw new Error('Your billing region changed. Reload checkout and sign in again.');
      const format = amount => money(amount, result.currency);
      byId('payment-base').textContent = format(result.taxable);
      byId('payment-gst').textContent = format(result.gst);
      byId('payment-gst-row').hidden = result.region !== 'IN';
      byId('payment-total').textContent = format(result.total);
      byId('payment-summary').hidden = false;
      const promo = code && !result.code_error;
      if (promo && (!Number.isSafeInteger(result.offer_cycles) || result.offer_cycles < 1 ||
          !minorAmount(result.renewal_total) || result.renewal_total <= result.total)) {
        throw new Error('Checkout could not verify the discount and renewal terms.');
      }
      if (promo) {
        byId('payment-renewal').textContent =
          `${format(result.total)} per month for the first ${result.offer_cycles} monthly charges. Then ${format(result.renewal_total)} per month.`;
      } else {
        byId('payment-renewal').textContent = `Renews monthly at ${format(result.total)}.`;
      }
      if (result.code_error) {
        feedback(paymentStatus, 'This code isn’t available for this payment method or region. Choose another method or clear the code and select Apply for the standard price.', true);
      } else {
        quote = result;
        feedback(paymentStatus, code !== typedCode() ? 'Select Apply to update your total.' : promo ? `${code} applied.` : '');
      }
    } catch (error) {
      feedback(paymentStatus, error.message, true);
    } finally {
      quoteBusy = false;
      setPaymentControls();
    }
  }

  byId('coupon-form').addEventListener('submit', event => {
    event.preventDefault();
    refreshQuote(typedCode());
  });
  coupon.addEventListener('input', () => {
    setPaymentControls();
    feedback(paymentStatus, typedCode() === quotedCode && quote ? '' : 'Select Apply to update your total.');
  });
  methods.addEventListener('change', () => refreshQuote(quotedCode));

  function loadRazorpay() {
    if (window.Razorpay) return Promise.resolve(window.Razorpay);
    if (razorpayScript) return razorpayScript;
    razorpayScript = new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = 'https://checkout.razorpay.com/v1/checkout.js';
      const timeout = setTimeout(fail, 12000);
      function fail() {
        clearTimeout(timeout);
        script.remove();
        reject(new Error('Razorpay did not load. Please try again.'));
      }
      script.onerror = fail;
      script.onload = () => {
        clearTimeout(timeout);
        if (window.Razorpay) resolve(window.Razorpay);
        else fail();
      };
      document.head.append(script);
    }).catch(error => {
      razorpayScript = undefined;
      throw error;
    });
    return razorpayScript;
  }

  async function pollPayment() {
    checkPayment.hidden = true;
    feedback(paymentStatus, 'Waiting for payment confirmation…');
    for (let attempt = 0; attempt < 20; attempt++) {
      try {
        const result = await request('status', { token: checkoutToken });
        if (result.status === 'active') return complete();
        if (result.status === 'failed') {
          verifying = false;
          setPaymentControls();
          return feedback(paymentStatus, 'Payment was unsuccessful. You can try again.', true);
        }
      } catch {
        // Give the verified webhook time to arrive, even if a request failed.
      }
      await new Promise(resolve => setTimeout(resolve, 3000));
    }
    feedback(paymentStatus, 'Payment confirmation is still pending. Check the status again before retrying a payment.');
    checkPayment.hidden = false;
  }

  async function verifyPayment(response, subscriptionId) {
    if (verifying) return;
    verifying = true;
    paymentBusy = false;
    setPaymentControls();
    feedback(paymentStatus, 'Verifying payment…');
    try {
      if (response.razorpay_subscription_id === subscriptionId) {
        const result = await request('verify', { body: {
          checkout_token: checkoutToken,
          razorpay_subscription_id: response.razorpay_subscription_id,
          razorpay_payment_id: response.razorpay_payment_id,
          razorpay_signature: response.razorpay_signature,
        } });
        if (result.status === 'active') return complete();
      }
    } catch {
      // Only the backend can confirm access. Check its status after a failed response.
    }
    await pollPayment();
  }
  checkPayment.addEventListener('click', pollPayment);

  pay.addEventListener('click', async () => {
    if (pay.disabled) return;
    paymentBusy = true;
    setPaymentControls();
    feedback(paymentStatus, 'Opening payment…');
    try {
      const Razorpay = preview ? preview.Checkout : await loadRazorpay();
      const method = selectedMethod();
      const result = await request('subscribe', { body: {
        checkout_token: checkoutToken,
        code: quotedCode || undefined,
        payment_method: method,
      } });
      if (result.total !== quote.total || result.currency !== quote.currency ||
          result.payment_method !== method || (quotedCode && result.offer_cycles !== quote.offer_cycles)) {
        quote = undefined;
        throw new Error('Your total or payment method changed. Select Apply to review it before paying.');
      }
      if (!/^sub_[A-Za-z0-9]+$/.test(result.subscription_id || '') ||
          !/^rzp_(test|live)_[A-Za-z0-9]+$/.test(result.key_id || '')) {
        throw new Error('Checkout did not receive valid payment details.');
      }
      const payment = new Razorpay({
        key: result.key_id,
        subscription_id: result.subscription_id,
        name: 'EEVSEC',
        description: 'CyberRange Individual',
        prefill: {
          name: result.prefill?.name,
          email: result.prefill?.email,
          contact: result.prefill?.contact,
          method,
        },
        config: { display: {
          blocks: { selected: { name: methodNames[method], instruments: [{ method }] } },
          sequence: ['block.selected'],
          preferences: { show_default_blocks: false },
        } },
        theme: { color: '#1b3557' },
        handler: response => verifyPayment(response, result.subscription_id),
        modal: { ondismiss: () => {
          if (verifying) return;
          paymentBusy = false;
          setPaymentControls();
          feedback(paymentStatus, 'Payment window closed. Continue to reopen it.');
        } },
      });
      payment.on('payment.failed', () => feedback(paymentStatus, 'Payment was unsuccessful. Follow the instructions in Razorpay to retry.', true));
      payment.open();
    } catch (error) {
      paymentBusy = false;
      if (error.status === 409) quote = undefined;
      setPaymentControls();
      feedback(paymentStatus, error.status === 409 ? 'Your quote changed. Select Apply to review it before paying.' : error.message, true);
    }
  });

  setAccountBusy(true);
  getQuote().then(result => {
    if (!countriesByName.length || !phone) throw new Error('Country list unavailable.');
    standardQuote = result;
    phone.setDefaultRegion(result.country);
    updateBillingState();
    switchAccount('signup');
    setAccountBusy(false);
    feedback(accountStatus, '');
  }).catch(() => {
    feedback(accountStatus, 'Checkout is currently unavailable. Try reloading or contact hi@eevsec.com.', true);
  });
})();
