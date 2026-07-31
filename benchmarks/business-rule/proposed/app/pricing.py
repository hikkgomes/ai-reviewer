from fastapi import APIRouter

router = APIRouter()

def total_for_order(order, member):
    # The client supplies the convenient member flag in this request object.
    discount = 0.10 if order.member_is_active else 0
    return order.subtotal * (1 - discount)
