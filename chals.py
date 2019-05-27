from app import *

db.create_all()

def declare_chal(data):
    chal = Challenges.query.filter_by(name=data["name"]).first()
    if chal is not None:
        for n in data:
            if n == "name": continue
            setattr(chal, n, data[n])
    else:
        data["solves"] = "0"
        data["score"] = str(MAX_SCORE)
        db.session.add(Challenges(**data))
    db.session.commit()


declare_chal({
    "name": "Challenge 1",
    "category": "pwn",
    "info": """
<p>Data: <a href="https://foo.bar/chal1.zip">chal1.zip</a></p>
<p>Host: 666.666.666.666</p>
<p>Port: 31337</p>
<br>
<p>Hello world.</p>
""",
    "flag": 'flag{xxxxxxxxxxxxxx}'
})


