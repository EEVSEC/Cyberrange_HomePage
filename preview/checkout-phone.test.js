const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const browserSource = ['libphonenumber-max-1.13.17.js', 'checkout-phone.js']
  .map(file => fs.readFileSync(path.join(__dirname, '../js', file), 'utf8'))
  .join('\n');

function phoneForm() {
  const elements = new Map();
  const document = {
    getElementById(id) {
      if (!elements.has(id)) {
        elements.set(id, {
          value: '',
          setAttribute() {},
          removeAttribute() {},
          addEventListener() {},
          focus() {},
        });
      }
      return elements.get(id);
    },
  };
  const context = vm.createContext({ document });
  context.window = context;
  vm.runInContext(browserSource, context);
  return { phone: context.crCheckoutPhone, input: document.getElementById('phone-number') };
}

const cases = [
  ['US','2025550100','+12025550100'],
  ['GB','02079460000','+442079460000'],
  ['IN','9876543210','+919876543210'],
  ['BR','11912345678','+5511912345678'],
  ['DE','015123456789','+4915123456789'],
  ['IT','0236618300','+390236618300'],
  ['AR','91123456789','+5491123456789'],
  ['JM','8762101234','+18762101234'],
];
for (const [region, value, expected] of cases) {
  test(`normalizes a ${region} contact number`, () => {
    const { phone, input } = phoneForm();
    phone.setDefaultRegion(region);
    input.value = value;
    assert.equal(phone.signupValue(), expected);
  });
}

test('rejects a missing country, malformed numbers and oversized values', () => {
  const { phone, input } = phoneForm();
  input.value = '2025550100';
  assert.equal(phone.signupValue(), undefined);
  phone.setDefaultRegion('US');
  for (const value of ['', ' ', '+', '202555010', '20255501001', 'text2025550100', '9'.repeat(10000), '٠١٢٣', '\u202e2025550100']) {
    input.value = value;
    assert.equal(phone.signupValue(), undefined);
  }
});
