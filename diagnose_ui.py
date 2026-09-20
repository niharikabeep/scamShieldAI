"""
Diagnose UI clickability using Chrome DevTools Protocol in Edge
"""
import asyncio
import json
import subprocess
import urllib.request
import websockets

CHECK_JS = """
(() => {
    const results = {};

    // 1. Check top element at center of URL input
    const urlInp = document.getElementById("url-input");
    if (urlInp) {
        const rect = urlInp.getBoundingClientRect();
        const elAtInput = document.elementFromPoint(rect.left + 30, rect.top + 15);
        results.inputTarget = {
            tag: elAtInput ? elAtInput.tagName : null,
            id: elAtInput ? elAtInput.id : null,
            className: elAtInput ? elAtInput.className : null,
            isUrlInput: elAtInput === urlInp
        };
    }

    // 2. Check top element at Nav Tab 2 (SMS)
    const smsTab = document.querySelectorAll(".nav-tab")[1];
    if (smsTab) {
        const rect = smsTab.getBoundingClientRect();
        const elAtTab = document.elementFromPoint(rect.left + 20, rect.top + 10);
        results.smsTabTarget = {
            tag: elAtTab ? elAtTab.tagName : null,
            id: elAtTab ? elAtTab.id : null,
            isTabOrChild: smsTab.contains(elAtTab)
        };
    }

    // 3. Test simulated click on sample chip 0 (Fake PayPal)
    const chip = document.querySelector(".sample-chip");
    if (chip) {
        chip.click();
        results.chipClickedUrl = urlInp ? urlInp.value : "";
    }

    // 4. Check modal status
    const modal = document.getElementById("api-modal");
    if (modal) {
        const comp = window.getComputedStyle(modal);
        results.modal = {
            display: comp.display,
            visibility: comp.visibility,
            pointerEvents: comp.pointerEvents,
            zIndex: comp.zIndex
        };
    }

    return results;
})()
"""

async def diagnose():
    proc = subprocess.Popen([
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        "--headless=new",
        "--remote-debugging-port=9222",
        "file:///C:/Users/nihar/.gemini/antigravity/scratch/scam-shield/index.html"
    ])
    await asyncio.sleep(2)

    try:
        req = urllib.request.urlopen("http://127.0.0.1:9222/json")
        tabs = json.loads(req.read())
        target_tab = None
        for t in tabs:
            if "scam-shield" in t.get("url", "") or "index.html" in t.get("url", ""):
                target_tab = t
                break
        if not target_tab:
            target_tab = tabs[0]

        print(f"Connected to: {target_tab.get('title')}")

        async with websockets.connect(target_tab["webSocketDebuggerUrl"]) as ws:
            await ws.send(json.dumps({"id": 1, "method": "Runtime.enable"}))
            await ws.recv()

            await ws.send(json.dumps({
                "id": 2,
                "method": "Runtime.evaluate",
                "params": {"expression": CHECK_JS, "returnByValue": True}
            }))

            while True:
                msg = json.loads(await ws.recv())
                if msg.get("id") == 2:
                    val = msg.get("result", {}).get("result", {}).get("value", {})
                    print("DIAGNOSTIC TEST RESULTS:")
                    print(json.dumps(val, indent=2))
                    break
                elif msg.get("method") == "Runtime.exceptionThrown":
                    print("EXCEPTION:", json.dumps(msg, indent=2))
                    break
    finally:
        proc.terminate()

if __name__ == "__main__":
    asyncio.run(diagnose())
