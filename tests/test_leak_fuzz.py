"""Leak test: thousands of generated prompts; no embedded secret may ever reach the provider."""
import random
import string

from tests.conftest import make_env


def luhn_card(rng):
    body = [rng.randint(0, 9) for _ in range(15)]
    body[0] = rng.choice([4, 5])
    total = sum((d * 2 - 9 if d * 2 > 9 else d * 2) if i % 2 == 0 else d for i, d in enumerate(body))
    return "".join(map(str, body)) + str((10 - total % 10) % 10)


def make_secret(rng):
    t = rng.choice(["email", "card", "sk", "aws", "gh", "pwd", "phone", "ssn"])
    A = string.ascii_letters + string.digits
    if t == "email":
        return f"{''.join(rng.choices(string.ascii_lowercase, k=8))}@{''.join(rng.choices(string.ascii_lowercase, k=6))}.com"
    if t == "card":
        return luhn_card(rng)
    if t == "sk":
        return "sk-proj-" + "".join(rng.choices(A, k=40))
    if t == "aws":
        return "AKIA" + "".join(rng.choices(string.ascii_uppercase + string.digits, k=16))
    if t == "gh":
        return "ghp_" + "".join(rng.choices(A, k=36))
    if t == "pwd":
        return "password: " + "".join(rng.choices(A, k=12))
    if t == "phone":
        return "080" + "".join(rng.choices(string.digits, k=8))
    return f"{rng.randint(100, 665)}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"


async def test_no_secret_ever_reaches_provider(tmp_path):
    rng = random.Random(1337)
    e = make_env(tmp_path)
    await e.unlock()
    words = "please summarise the following notes and then reply politely to everyone involved thanks".split()
    sent_secrets = []
    for _ in range(400):
        parts, secrets_ = [], []
        for _ in range(rng.randint(1, 4)):
            s = make_secret(rng)
            secrets_.append(s.replace("password: ", "") if s.startswith("password: ") else s)
            parts.append(" ".join(rng.choices(words, k=rng.randint(2, 6))) + " " + s)
        prompt = " . ".join(parts)
        r = await e.chat(prompt, session=f"s{rng.randint(0, 5)}", stream=rng.random() < 0.3)
        assert r.status_code == 200, r.text
        sent_secrets += secrets_
    blob = "\n".join(__import__("json").dumps(b) for b in e.log)
    leaked = [s for s in sent_secrets if s in blob]
    assert not leaked, f"{len(leaked)} secrets leaked, e.g. {leaked[:2]}"
    assert len(e.log) == 400
    await e.client.aclose()
