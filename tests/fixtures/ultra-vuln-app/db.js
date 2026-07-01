// Toy in-memory data layer for the fixture. Not a real database.
const invoices = {
  'inv_1': { id: 'inv_1', userId: 'u_alice', amount: 4200, tenant: 't_1' },
  'inv_2': { id: 'inv_2', userId: 'u_bob', amount: 990, tenant: 't_2' },
};
const orders = {
  'ord_1': { id: 'ord_1', userId: 'u_alice', total: 4200 },
  'ord_2': { id: 'ord_2', userId: 'u_bob', total: 990 },
};

module.exports = {
  getInvoice: (id) => invoices[id],
  getOrder: (id) => orders[id],
  refund: (paymentId) => ({ refunded: paymentId }),
};
