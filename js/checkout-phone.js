(() => {
  'use strict';

  const lib = window.libphonenumber;
  if (!lib) return;

  const country = document.getElementById('phone-country');
  const number = document.getElementById('phone-number');
  const error = document.getElementById('phone-error');
  const popup = document.getElementById('phone-country-popup');
  const list = document.getElementById('phone-country-results');
  const empty = document.getElementById('phone-country-empty');
  const names = new Intl.DisplayNames(['en'], { type: 'region' });
  const countries = window.crCheckoutCountries || {};
  const examples = window.crCheckoutPhoneExamples || {};
  const regions = lib.getCountries().map(id => {
    const name = countries[id]?.[0] || names.of(id);
    const code = lib.getCountryCallingCode(id);
    return { id, name, code, label: `${name} (+${code})` };
  }).sort((a, b) => a.name.localeCompare(b.name));
  const byRegion = new Map(regions.map(region => [region.id, region]));
  const specialTypes = new Set(['PREMIUM_RATE', 'SHARED_COST', 'UAN']);
  const isTenDigitPlan = region => region?.code === '91' || region?.code === '1';
  let selected;
  let matches = [];
  let activeIndex = -1;

  function clearError() {
    if (error.textContent) error.textContent = '';
    number.removeAttribute('aria-invalid');
    country.removeAttribute('aria-invalid');
  }

  function showError(field, message, focus = false) {
    clearError();
    error.textContent = message;
    field.setAttribute('aria-invalid', 'true');
    if (focus) field.focus();
  }

  function updateActive(index) {
    list.children[activeIndex]?.setAttribute('aria-selected', 'false');
    activeIndex = index;
    const option = list.children[index];
    if (!option) {
      country.removeAttribute('aria-activedescendant');
      return;
    }
    option.setAttribute('aria-selected', 'true');
    country.setAttribute('aria-activedescendant', option.id);
    const optionRect = option.getBoundingClientRect();
    const popupRect = popup.getBoundingClientRect();
    if (optionRect.top < popupRect.top) popup.scrollTop += optionRect.top - popupRect.top;
    else if (optionRect.bottom > popupRect.bottom) popup.scrollTop += optionRect.bottom - popupRect.bottom;
  }

  function showCountries(query = '') {
    const search = query.trim().toLowerCase();
    const dial = /^\+?\d+$/.test(search) ? search.replace(/^\+/, '') : '';
    matches = regions.filter(region => dial ? region.code.startsWith(dial) :
      region.label.toLowerCase().includes(search) || region.id.toLowerCase() === search);
    const options = matches.map(region => {
      const option = document.createElement('li');
      option.id = 'phone-option-' + region.id;
      option.dataset.region = region.id;
      option.setAttribute('role', 'option');
      option.setAttribute('aria-selected', 'false');
      option.textContent = region.label;
      return option;
    });
    list.replaceChildren(...options);
    popup.hidden = false;
    empty.hidden = options.length > 0;
    country.setAttribute('aria-expanded', 'true');
    activeIndex = -1;
    updateActive(search ? 0 : matches.indexOf(selected));
  }

  function closeCountries() {
    popup.hidden = true;
    country.setAttribute('aria-expanded', 'false');
    country.removeAttribute('aria-activedescendant');
  }

  function setRegion(region) {
    selected = region;
    country.value = region?.label || '';
    number.maxLength = isTenDigitPlan(region) ? 10 : 15;
    number.placeholder = examples[region?.id] || '';
    closeCountries();
    clearError();
  }

  function chooseRegion(region) {
    if (!region) return;
    setRegion(region);
    if (number.value.length > number.maxLength) {
      showError(number, `Enter the 10-digit number for ${region.name}.`);
    }
  }

  country.addEventListener('focus', () => country.select());
  country.addEventListener('click', () => {
    if (popup.hidden) {
      country.select();
      showCountries();
    }
  });
  country.addEventListener('input', () => {
    clearError();
    showCountries(country.value);
  });
  country.addEventListener('blur', () => {
    const exactMatches = matches.filter(region =>
      [region.id.toLowerCase(), region.name.toLowerCase(), region.label.toLowerCase(), '+' + region.code].includes(country.value.trim().toLowerCase()));
    if (!popup.hidden && exactMatches.length === 1) chooseRegion(exactMatches[0]);
    else {
      country.value = selected?.label || '';
      closeCountries();
    }
  });
  country.addEventListener('keydown', event => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      if (popup.hidden) showCountries();
      const step = event.key === 'ArrowDown' ? 1 : -1;
      if (matches.length) updateActive(Math.max(0, Math.min(matches.length - 1, activeIndex + step)));
    } else if (event.key === 'Enter' && !popup.hidden) {
      event.preventDefault();
      chooseRegion(matches[activeIndex]);
    } else if (event.key === 'Escape' && !popup.hidden) {
      event.preventDefault();
      country.value = selected?.label || '';
      closeCountries();
    }
  });
  list.addEventListener('mousedown', event => {
    if (event.target.closest('[role="option"]')) event.preventDefault();
  });
  list.addEventListener('click', event => {
    const option = event.target.closest('[role="option"]');
    if (option) chooseRegion(byRegion.get(option.dataset.region));
  });

  function parse(value, region) {
    return lib.parsePhoneNumberFromString(value, { defaultCountry: region?.id, extract: false });
  }

  function validate(strict) {
    const value = number.value;
    if (!selected) {
      if (strict) showError(country, 'Select a country calling code.', true);
      return;
    }
    if (!strict && !value) return;
    if (!/^[0-9]{1,15}$/.test(value)) {
      showError(number, 'Enter a phone number using digits only.', strict);
      return;
    }
    if (isTenDigitPlan(selected) && value.length !== 10) {
      showError(number, `Enter all 10 digits for ${selected.name}.`, strict);
      return;
    }
    const parsed = parse(value, selected);
    if (!parsed?.isPossible() || (strict && (!parsed.isValid() || !/^\+[1-9][0-9]{1,14}$/.test(parsed.number)))) {
      showError(number, `Enter a valid phone number for ${selected.name}, including the area code if needed.`, strict);
      return;
    }
    if (parsed.countryCallingCode !== selected.code) {
      showError(country, 'Choose the calling code that matches your phone number.', strict);
      return;
    }
    if (strict && specialTypes.has(parsed.getType())) {
      showError(number, 'Enter a personal or business contact number.', true);
      return;
    }
    clearError();
    return parsed.number;
  }

  number.addEventListener('beforeinput', event => {
    const incoming = event.data ?? event.dataTransfer?.getData('text/plain');
    if (incoming && /[^0-9]/.test(incoming)) event.preventDefault();
  });
  number.addEventListener('paste', event => {
    const raw = event.clipboardData?.getData('text/plain');
    if (!raw) return;
    event.preventDefault();
    const value = raw.replace(/^[ \u00A0\u202F]+|[ \u00A0\u202F]+$/g, '');
    if (raw.length > 64 || !/^\+?[0-9 .()\u00A0\u202F-]+$/.test(value)) {
      showError(number, 'Paste a phone number without letters, extensions or other text.');
      return;
    }

    const digits = value.replace(/[^0-9]/g, '');
    const international = value.startsWith('+') || digits.startsWith('00');
    if (international) {
      const candidate = '+' + (value.startsWith('+') ? digits : digits.slice(2));
      const parsed = parse(candidate);
      let region = byRegion.get(parsed?.country);
      if (!region && parsed?.countryCallingCode === selected?.code) region = selected;
      const withTrunkZero = parsed && `+${parsed.countryCallingCode}0${parsed.nationalNumber}`;
      if (!parsed?.isValid() || !region || (candidate !== parsed.number && candidate !== withTrunkZero) ||
          !/^\+[1-9][0-9]{1,14}$/.test(parsed.number) ||
          (isTenDigitPlan(region) && parsed.nationalNumber.length !== 10)) {
        showError(number, 'Paste a valid international phone number or select its calling code.');
        return;
      }
      setRegion(region);
      number.value = parsed.nationalNumber;
      return;
    }

    let replacement = digits;
    const start = number.selectionStart;
    const end = number.selectionEnd;
    // Only remove a trunk or a repeated calling code for a fully pasted number that parses.
    if (digits.length > number.maxLength && start === 0 && end === number.value.length && selected) {
      const parsed = parse(digits, selected);
      if (parsed?.isValid() && parsed.countryCallingCode === selected.code &&
          (digits === '0' + parsed.nationalNumber || digits === selected.code + parsed.nationalNumber)) {
        replacement = parsed.nationalNumber;
      }
    }
    if (!replacement || number.value.length - (end - start) + replacement.length > number.maxLength) {
      showError(number, `Enter up to ${number.maxLength} digits for this calling code.`);
      return;
    }
    number.setRangeText(replacement, start, end, 'end');
    clearError();
  });
  number.addEventListener('input', () => {
    const value = number.value;
    if (/[^0-9]/.test(value)) {
      const caret = value.slice(0, number.selectionStart).replace(/[^0-9]/g, '').length;
      number.value = value.replace(/[^0-9]/g, '');
      number.setSelectionRange(caret, caret);
    }
    clearError();
  });
  number.addEventListener('blur', () => validate(false));
  let defaultRegion;
  document.getElementById('account-form').addEventListener('reset', () => {
    queueMicrotask(() => setRegion(defaultRegion));
  });

  window.crCheckoutPhone = {
    clearError,
    setDefaultRegion(id) {
      defaultRegion = byRegion.get(id);
      setRegion(defaultRegion);
    },
    signupValue: () => validate(true),
  };
})();
