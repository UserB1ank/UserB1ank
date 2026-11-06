"""Render an animated profile dashboard using GitHub's visible contribution data."""

import argparse
import json
import os
from datetime import date, datetime, timezone
from html import escape
from pathlib import Path
from urllib.request import Request, urlopen


QUERY = """
query($login: String!) {
  user(login: $login) {
    contributionsCollection {
      totalCommitContributions
      totalPullRequestContributions
      totalIssueContributions
      contributionCalendar {
        totalContributions
        weeks {
          contributionDays { date weekday contributionCount contributionLevel }
        }
      }
    }
  }
}
"""

COLORS = {
    "NONE": "#172235",
    "FIRST_QUARTILE": "#233f55",
    "SECOND_QUARTILE": "#2f7185",
    "THIRD_QUARTILE": "#46abbd",
    "FOURTH_QUARTILE": "#77e2ea",
}


def fetch_contributions(login):
    request = Request(
        "https://api.github.com/graphql",
        data=json.dumps({"query": QUERY, "variables": {"login": login}}).encode(),
        headers={
            "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
            "Content-Type": "application/json",
            "User-Agent": "UserB1ank-profile-visuals",
        },
    )
    with urlopen(request, timeout=45) as response:
        payload = json.load(response)
    if payload.get("errors"):
        raise RuntimeError(json.dumps(payload["errors"]))
    user = payload.get("data", {}).get("user")
    if not user:
        raise ValueError(f"GitHub user not found: {login}")
    return user["contributionsCollection"]


def longest_streak(days):
    best = current = 0
    previous = None
    for day in sorted(days, key=lambda item: item["date"]):
        current_date = date.fromisoformat(day["date"])
        consecutive = previous is not None and (current_date - previous).days == 1
        current = (current + 1 if consecutive else 1) if day["contributionCount"] else 0
        best = max(best, current)
        previous = current_date
    return best


def render(collection, login):
    calendar = collection["contributionCalendar"]
    weeks = calendar["weeks"]
    days = [day for week in weeks for day in week["contributionDays"]]
    if not days or not weeks:
        raise ValueError("GitHub returned an empty contribution calendar")

    weekly = [sum(day["contributionCount"] for day in week["contributionDays"]) for week in weeks]
    peak = max(weekly) or 1
    points = [(42 + i * 916 / max(len(weekly) - 1, 1), 318 - value * 58 / peak) for i, value in enumerate(weekly)]
    line = "M" + " L".join(f"{x:.2f},{y:.2f}" for x, y in points)
    area = line + f" L{points[-1][0]:.2f},320 L42,320 Z"
    updated = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    first, last = min(day["date"] for day in days), max(day["date"] for day in days)

    svg = [f'''<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="570" viewBox="0 0 1000 570" role="img" aria-labelledby="title desc">
<title id="title">{escape(login)} — GitHub contribution dashboard</title>
<desc id="desc">{calendar['totalContributions']} contributions from {first} to {last}. Commit contributions, pull requests, issues, longest contribution streak, weekly trend and daily heatmap.</desc>
<defs>
  <linearGradient id="area" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#63d8ea" stop-opacity=".24"/><stop offset="1" stop-color="#63d8ea" stop-opacity="0"/></linearGradient>
  <linearGradient id="edge"><stop stop-color="#ffae86"/><stop offset="1" stop-color="#63d8ea"/></linearGradient>
</defs>
<style>
text{{font-family:'SFMono-Regular',Consolas,'Liberation Mono',monospace}}
.headline{{font-family:'Trebuchet MS','DejaVu Sans',sans-serif}}
.beacon{{animation:beacon 3s cubic-bezier(.45,0,.3,1) infinite}}
.appear{{animation:appear 1.4s cubic-bezier(.32,.72,0,1) both}}
@keyframes beacon{{0%,100%{{opacity:.3}}50%{{opacity:1}}}}
@keyframes appear{{from{{opacity:0;transform:translateY(5px)}}to{{opacity:1;transform:translateY(0)}}}}
@media(prefers-reduced-motion:reduce){{.beacon,.appear{{animation:none}}}}
</style>
<rect x="1" y="1" width="998" height="568" rx="22" fill="#080e18" stroke="#26344a"/>
<rect x="8" y="8" width="984" height="554" rx="16" fill="#0d1523"/>
<path d="M28 1H972" stroke="url(#edge)" stroke-width="2"/>
<text x="40" y="44" fill="#63d8ea" font-size="12" letter-spacing="2">GITHUB / THE LAST 12 MONTHS</text>
<text x="38" y="87" class="headline" fill="#edf2ff" font-size="35" font-weight="700">The commit room<tspan fill="#ffae86">.</tspan></text>
<circle cx="707" cy="43" r="4" fill="#8bdfb2" class="beacon"/>
<text x="723" y="48" fill="#9daec5" font-size="12">REFRESHED {updated} UTC</text>
<text x="959" y="84" fill="#63d8ea" text-anchor="end" font-size="16">{calendar['totalContributions']:,} contributions</text>
''']

    stats = [
        ("COMMITS", collection["totalCommitContributions"], "#ffae86", "commit contributions"),
        ("PULL REQUESTS", collection["totalPullRequestContributions"], "#63d8ea", "opened in this period"),
        ("ISSUES", collection["totalIssueContributions"], "#b5b5f4", "opened in this period"),
        ("BEST STREAK", longest_streak(days), "#a7dcb7", "consecutive active days"),
    ]
    for index, (label, value, color, caption) in enumerate(stats):
        x = 33 + index * 235
        svg.append(f'''<rect x="{x}" y="111" width="229" height="108" rx="14" fill="#101c2d"/>
<rect x="{x+4}" y="115" width="221" height="100" rx="10" fill="#111b2b"/>
<text x="{x+18}" y="138" fill="#8e9fb8" font-size="11" letter-spacing="1.4">{label}</text>
<text x="{x+16}" y="179" class="headline" fill="{color}" font-size="38" font-weight="700">{value:,}</text>
<text x="{x+18}" y="201" fill="#8e9fb8" font-size="10">{caption}</text>''')

    svg.append(f'''<text x="42" y="247" fill="#8fa2bb" font-size="11" letter-spacing="1.5">WEEKLY CONTRIBUTION PULSE</text>
<path d="M42 320H958M42 286H958" stroke="#223047" stroke-opacity=".5"/>
<path d="{area}" fill="url(#area)" class="appear"/>
<path d="{line}" fill="none" stroke="#63d8ea" stroke-width="2.2" stroke-linejoin="round" class="appear"/>
<circle cx="{points[-1][0]:.2f}" cy="{points[-1][1]:.2f}" r="4" fill="#ffae86" class="beacon"/>
<text x="42" y="353" fill="#8fa2bb" font-size="11" letter-spacing="1.5">ONE PIXEL. ONE DAY. SOMETHING BUILT.</text>''')

    step = 916 / len(weeks)
    previous_month = None
    for week_index, week in enumerate(weeks):
        month = date.fromisoformat(week["contributionDays"][0]["date"]).strftime("%b")
        x = 42 + week_index * step
        if month != previous_month and week_index < len(weeks) - 2:
            svg.append(f'<text x="{x:.2f}" y="381" fill="#8498b4" font-size="10">{month}</text>')
            previous_month = month
        for day in week["contributionDays"]:
            y = 392 + day["weekday"] * 17
            color = COLORS[day["contributionLevel"]]
            tooltip = escape(f"{day['date']}: {day['contributionCount']} contributions")
            svg.append(f'<rect x="{x:.2f}" y="{y}" width="{step-4:.2f}" height="13" rx="3" fill="{color}"><title>{tooltip}</title></rect>')

    svg.append(f'''<text x="42" y="539" fill="#8194af" font-size="10">{first} — {last} / GITHUB CONTRIBUTIONS</text>
<text x="784" y="538" fill="#8194af" font-size="10">LESS</text>''')
    for index, color in enumerate(COLORS.values()):
        svg.append(f'<rect x="{822 + index*18}" y="528" width="12" height="12" rx="3" fill="{color}"/>')
    svg.append('<text x="921" y="538" fill="#8194af" font-size="10">MORE</text></svg>')
    return "\n".join(svg)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("dist/activity.svg"))
    parser.add_argument("--data", type=Path, help="Use a local GraphQL response for a preview")
    args = parser.parse_args()
    login = os.environ.get("PROFILE_USER", "UserB1ank")
    if args.data:
        collection = json.loads(args.data.read_text())["data"]["user"]["contributionsCollection"]
    else:
        collection = fetch_contributions(login)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(collection, login))
    print(f"Rendered contribution dashboard: {args.output}")


if __name__ == "__main__":
    main()
