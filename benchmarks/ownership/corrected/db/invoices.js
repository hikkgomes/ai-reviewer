export function invoiceForTenant(prisma, tenantId, id) {
  return prisma.invoice.findFirst({ where: { id, tenantId } });
}
