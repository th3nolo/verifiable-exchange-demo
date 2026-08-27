"""Captures docs/ui.png from the live exchange.

    python3 docs/capture-ui.py docs/ui.png

Why this is a script and not a screenshot somebody takes by hand.

The image in the README went stale twice. The version before this one was
captured on 14 August 2026 and showed `NEX-USDC` and a 1-second chart button.
Both were gone by 17 August: the markets are MERKLE-USDC, ETH-USDC and
BTC-USDC, and the buttons are 15s, 5m, 15m, 1h and 4h. So the README argued for
a page that no longer existed, and nothing caught it. A reader who opened
exchange.th3nolo.com saw a different product from the one the README showed.

The checks below are the point of the file. The script refuses to write the
image unless the page it captured is the page this repository ships. A stale
tab, a half-loaded page or a deploy that has not landed all fail loudly instead
of becoming the next stale image.

The market check is the one that is easy to leave out. On 17 August a generator
change met every assertion in `docs/GENERATOR-RFC.md` section 5 and stopped the
price moving: the band over 25 minutes fell from 2.84% to 0.83%. Every symbol
and every button was correct, so a screenshot taken that hour would have passed
a check that only reads names, and the README would have shown a flat line.
`--min-band` reads the candles and refuses a market that is not moving.

Needs `pip install playwright` and `playwright install chromium`.
"""
import argparse
import json
import sys
import urllib.request

from playwright.sync_api import sync_playwright

SYMBOLS = ("MERKLE-USDC", "ETH-USDC", "BTC-USDC")
BUTTONS = ("15s", "5m", "15m", "1h", "4h")
GONE = ("NEX-USDC", "ALFA", "BRAVO", "CHARLIE")


def price_band(host, symbol, interval, buckets):
    """The high-to-low range over recent candles, as a percent of the low.

    Read from the exchange, not from the page, because a number the page
    computed is a number this check would be trusting rather than testing.
    """
    url = f"{host}/candles?symbol={symbol}&interval={interval}&n={buckets}"
    with urllib.request.urlopen(url, timeout=30) as answer:
        candles = json.load(answer)
    traded = [c for c in candles if c["trades"]]
    if not traded:
        return 0.0
    high = max(c["high"] for c in traded)
    low = min(c["low"] for c in traded)
    return (high - low) / low * 100 if low else 0.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--host", default="https://exchange.th3nolo.com")
    ap.add_argument("--settle", type=int, default=60,
                    help="seconds to let the book, the candles and the "
                         "profit-and-loss curve fill from the live feed")
    ap.add_argument("--min-band", type=float, default=1.0,
                    help="refuse if the price moved less than this percent "
                         "over the last 100 fifteen-second candles")
    args = ap.parse_args()

    refused = []

    for symbol in SYMBOLS:
        band = price_band(args.host, symbol, 15, 100)
        if band < args.min_band:
            refused.append(
                f"{symbol} moved {band:.2f}% over the last 25 minutes, under "
                f"the {args.min_band:.2f}% floor. The market is flat, so the "
                f"image would show a flat line."
            )

    with sync_playwright() as p:
        browser = p.chromium.launch()
        # 1760 and not 1680. The verification strip is what the README argues
        # about, and it carries two lengths of every label: `chain checked` on a
        # window with room for it, `chain` under 1700px, where the long form no
        # longer fits on one line. The strip is the first thing the image is
        # read for, so the image is captured at a width that shows the long
        # form. See `.verify .sm` in services/static/app.css.
        page = browser.new_page(
            viewport={"width": 1760, "height": 1150},
            device_scale_factor=2,
            color_scheme="dark",
        )
        # Not networkidle. The page polls the feed for as long as it is open,
        # so the network never goes idle and that wait always times out.
        page.goto(args.host + "/", wait_until="load", timeout=60_000)
        page.wait_for_timeout(args.settle * 1000)

        text = page.inner_text("body")
        for name in GONE:
            if name in text:
                refused.append(f"the page still shows {name}")
        for name in SYMBOLS:
            if name not in text:
                refused.append(f"the page does not show {name}")
        for button in BUTTONS:
            if button not in text:
                refused.append(f"the page has no {button} chart button")

        if refused:
            print("REFUSED, the image was not written:")
            for line in refused:
                print("  " + line)
            browser.close()
            return 1

        page.screenshot(path=args.out)
        print(f"wrote {args.out}")
        browser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
