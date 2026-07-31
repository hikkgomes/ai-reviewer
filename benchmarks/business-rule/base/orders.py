from app.pricing import total_for_order

def checkout(order, member, db):
    return total_for_order(order, db.member_for_user(member.user_id))
