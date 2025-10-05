"""Manager for pons."""

import os
import secrets
import json
import aiosqlite

PONDATA = {}

async def init():
    ponfolders = [f for f in os.listdir("pons") if os.path.isdir(os.path.join("pons", f))]
    PONDATA["pons"] = {}
    for pon in ponfolders:
        if os.path.exists("pons/" + pon + "/meta.json"):
            with open("pons/" + pon + "/meta.json", "r", encoding="utf-8") as f:
                meta = f.read()
            try:
                meta_json = json.loads(meta)
                pon_id = meta_json["id"]
                PONDATA["pons"][pon_id] = meta_json
            except Exception:
                pass

async def pull(user: str, pon: str):
    await init()
    if pon not in PONDATA["pons"]:
        return None
    async with aiosqlite.connect("database.db") as db:
        async with db.execute("SELECT coins FROM users WHERE username = ?", (user,)) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            coins = row[0]
    if coins < PONDATA["pons"][pon].get("cost", 1):
        return None
    async with aiosqlite.connect("database.db") as db:
        await db.execute(f"CREATE TABLE IF NOT EXISTS '{user}' (id INTEGER PRIMARY KEY)")
        cursor = await db.execute(f"PRAGMA table_info('{user}')")
        columns = await cursor.fetchall()
        column_names = [col[1] for col in columns]
        
        if pon not in column_names:
            await db.execute(f"ALTER TABLE '{user}' ADD COLUMN '{pon}' TEXT")
        card = secrets.choice(PONDATA["pons"][pon]["cards"])
        if "varieties" in card:
            variety = secrets.choice(card["varieties"])
            card_id = f"{card['id']}/{variety['id']}"
        else:
            card_id = card["id"]
        await db.execute(f"INSERT INTO '{user}' ('{pon}') VALUES (?)", (card_id,))
        await db.execute("UPDATE users SET coins = coins - ? WHERE username = ?", (PONDATA["pons"][pon].get("cost", 1), user))
        await db.commit()
    return card_id