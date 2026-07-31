from fastapi import APIRouter

router = APIRouter()

def total_for_order(order, member):
    discount = 0.10 if member.is_active else 0
    return order.subtotal * (1 - discount)
