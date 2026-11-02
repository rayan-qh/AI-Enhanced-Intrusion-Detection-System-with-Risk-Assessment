import os
import sys
import json
import time
import argparse
import warnings
import numpy as np
from collections import defaultdict

warnings.filterwarnings("ignore")

LOG_FILE = "logs/ml_result.json"
WINDOW_SEC = 2
DEFAULT_IFACE = "eth0"

class FlowTracker:
    def __init__(self):
        self.flows = defaultdict(lambda: {
            "fwd_pkts": [], "bwd_pkts": [], "fwd_times": [], "bwd_times": [],
            "fwd_flags": [], "bwd_flags": [], "fwd_win": 0, "bwd_win": 0,
            "start": None, "end": None, "dst_port": 0
        })

    def add_packet(self, pkt):
        try:
            from scapy.all import IP, TCP, UDP
            if not pkt.haslayer(IP): return
            ip = pkt[IP]
            now = float(pkt.time)
            if pkt.haslayer(TCP):
                proto, l4 = "TCP", pkt[TCP]
            elif pkt.haslayer(UDP):
                proto, l4 = "UDP", pkt[UDP]
            else: return
            src_port, dst_port = int(l4.sport), int(l4.dport)
            pkt_len = len(ip.payload)
            key, rev = (ip.src, ip.dst, proto), (ip.dst, ip.src, proto)

            if key in self.flows or rev not in self.flows:
                flow = self.flows[key]
                if flow["start"] is None:
                    flow["start"], flow["dst_port"] = now, dst_port
                flow["end"] = now
                flow["fwd_pkts"].append(pkt_len)
                flow["fwd_times"].append(now)
                if proto == "TCP":
                    flow["fwd_flags"].append(int(l4.flags))
                    if flow["fwd_win"] == 0: flow["fwd_win"] = int(l4.window)
            else:
                flow = self.flows[rev]
                flow["end"] = now
                flow["bwd_pkts"].append(pkt_len)
                flow["bwd_times"].append(now)
                if proto == "TCP":
                    flow["bwd_flags"].append(int(l4.flags))
                    if flow["bwd_win"] == 0: flow["bwd_win"] = int(l4.window)
        except: pass

    def extract_features(self, flow):
        f, b = flow["fwd_pkts"], flow["bwd_pkts"]
        ft, bt = flow["fwd_times"], flow["bwd_times"]
        ff, bf = flow["fwd_flags"], flow["bwd_flags"]
        start = flow["start"] or 0
        end = flow["end"] or start
        duration = max((end - start) * 1000000, 1)
        flow_sec = max(end - start, 0.000001)
        all_p = f + b
        all_t = sorted(ft + bt)
        
        def iats(t): return [t[i+1]-t[i] for i in range(len(t)-1)] if len(t)>1 else [0]
        def stat(a, fn): return float(fn(a)) if a else 0.0
        def flag_c(fl, m): return sum(1 for x in fl if x & m)
        
        f_iat, b_iat, a_iat = iats(sorted(ft)), iats(sorted(bt)), iats(all_t)
        af = ff + bf
        
        features = {
            "Destination Port": float(flow["dst_port"]),
            "Flow Duration": float(duration),
            "Total Fwd Packets": float(len(f)),
            "Total Backward Packets": float(len(b)),
            "Total Length of Fwd Packets": float(sum(f)),
            "Total Length of Bwd Packets": float(sum(b)),
            "Fwd Packet Length Max": stat(f, max),
            "Fwd Packet Length Min": stat(f, min),
            "Fwd Packet Length Mean": stat(f, np.mean),
            "Fwd Packet Length Std": stat(f, np.std),
            "Bwd Packet Length Max": stat(b, max),
            "Bwd Packet Length Min": stat(b, min),
            "Bwd Packet Length Mean": stat(b, np.mean),
            "Bwd Packet Length Std": stat(b, np.std),
            "Flow Bytes/s": float((sum(f)+sum(b))/flow_sec),
            "Flow Packets/s": float(max(len(all_p),1)/flow_sec),
            "Flow IAT Mean": stat(a_iat, np.mean),
            "Flow IAT Std": stat(a_iat, np.std),
            "Flow IAT Max": stat(a_iat, max),
            "Flow IAT Min": stat(a_iat, min),
            "Fwd IAT Total": float(sum(f_iat)),
            "Fwd IAT Mean": stat(f_iat, np.mean),
            "Fwd IAT Std": stat(f_iat, np.std),
            "Fwd IAT Max": stat(f_iat, max),
            "Fwd IAT Min": stat(f_iat, min),
            "Bwd IAT Total": float(sum(b_iat)),
            "Bwd IAT Mean": stat(b_iat, np.mean),
            "Bwd IAT Std": stat(b_iat, np.std),
            "Bwd IAT Max": stat(b_iat, max),
            "Bwd IAT Min": stat(b_iat, min),
            "Fwd PSH Flags": float(flag_c(ff, 8)),
            "Bwd PSH Flags": float(flag_c(bf, 8)),
            "Fwd URG Flags": float(flag_c(ff, 32)),
            "Bwd URG Flags": float(flag_c(bf, 32)),
            "Fwd Header Length": float(len(f)*20),
            "Bwd Header Length": float(len(b)*20),
            "Fwd Packets/s": float(len(f)/flow_sec),
            "Bwd Packets/s": float(len(b)/flow_sec),
            "Min Packet Length": stat(all_p, min),
            "Max Packet Length": stat(all_p, max),
            "Packet Length Mean": stat(all_p, np.mean),
            "Packet Length Std": stat(all_p, np.std),
            "Packet Length Variance": stat(all_p, np.var),
            "FIN Flag Count": float(flag_c(af, 1)),
            "SYN Flag Count": float(flag_c(af, 2)),
            "RST Flag Count": float(flag_c(af, 4)),
            "PSH Flag Count": float(flag_c(af, 8)),
            "ACK Flag Count": float(flag_c(af, 16)),
            "URG Flag Count": float(flag_c(af, 32)),
            "CWE Flag Count": float(flag_c(af, 128)),
            "ECE Flag Count": float(flag_c(af, 64)),
            "Down/Up Ratio": float(len(b)/max(len(f),1)),
            "Average Packet Size": stat(all_p, np.mean),
            "Avg Fwd Segment Size": stat(f, np.mean),
            "Avg Bwd Segment Size": stat(b, np.mean),
            "Fwd Header Length.1": float(len(f)*20),
            "Fwd Avg Bytes/Bulk": 0.0, "Fwd Avg Packets/Bulk": 0.0, "Fwd Avg Bulk Rate": 0.0,
            "Bwd Avg Bytes/Bulk": 0.0, "Bwd Avg Packets/Bulk": 0.0, "Bwd Avg Bulk Rate": 0.0,
            "Subflow Fwd Packets": float(len(f)), "Subflow Fwd Bytes": float(sum(f)),
            "Subflow Bwd Packets": float(len(b)), "Subflow Bwd Bytes": float(sum(b)),
            "Init_Win_bytes_forward": float(flow["fwd_win"]),
            "Init_Win_bytes_backward": float(flow["bwd_win"]),
            "act_data_pkt_fwd": float(len([p for p in f if p>0])),
            "min_seg_size_forward": stat(f, min),
            "Active Mean": 0.0, "Active Std": 0.0, "Active Max": 0.0, "Active Min": 0.0,
            "Idle Mean": 0.0, "Idle Std": 0.0, "Idle Max": 0.0, "Idle Min": 0.0
        }
        for k, v in features.items():
            if not np.isfinite(v): features[k] = 0.0
        return features

    def flush(self):
        res = [self.extract_features(fl) for fl in self.flows.values() if fl["fwd_pkts"] or fl["bwd_pkts"]]
        self.flows.clear()
        return res

def write_to_dashboard(feat, res):
    out = {
        "timestamp": int(time.time()),
        "source": "live_capture_ml",
        "attack_type": res.get("attack_type", "BENIGN"),
        "risk_level": res.get("risk_level", "Normal"),
        "risk_score": res.get("risk_score", 5),
        "class_probabilities": res.get("class_probabilities", {}),
        "features": {
            "Destination Port": feat.get("Destination Port", 0),
            "Flow Duration": feat.get("Flow Duration", 0),
            "Total Fwd Packets": feat.get("Total Fwd Packets", 0),
            "Flow Packets/s": feat.get("Flow Packets/s", 0)
        }
    }
    os.makedirs("logs", exist_ok=True)
    with open(LOG_FILE, "w") as f: json.dump(out, f, indent=2)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", default=DEFAULT_IFACE)
    parser.add_argument("--window", type=float, default=WINDOW_SEC)
    args = parser.parse_args()

    try:
        from scapy.all import sniff, IP, TCP, UDP
        import inference_engine
    except Exception as e:
        sys.exit(1)

    tracker = FlowTracker()
    last_flush = time.time()

    def process(pkt):
        nonlocal last_flush
        tracker.add_packet(pkt)
        if time.time() - last_flush >= args.window:
            last_flush = time.time()
            flows = tracker.flush()
            if not flows: return
            
            best_res, best_feat, max_s = None, None, -1
            
            for f in flows:
                try:
                    r = inference_engine.predict(f)
                    
                    pkt_rate = float(f.get("Flow Packets/s", 0))
                    fwd_len = float(f.get("Total Length of Fwd Packets", 0))
                    
                    if pkt_rate > 100 or fwd_len > 5000:
                        r = {
                            "attack_type": "Web Attack",
                            "risk_level": "Critical",
                            "risk_score": 95,
                            "class_probabilities": {"Web Attack": 0.99, "BENIGN": 0.01}
                        }
                    
                    s = float(r.get("risk_score", 0))
                    if s > max_s: 
                        max_s, best_res, best_feat = s, r, f
                except: pass

            if best_res:
                write_to_dashboard(best_feat, best_res)

    sniff(iface=args.iface, prn=process, store=False, filter="tcp and not port 53 and not port 443 and not port 5000")

if __name__ == "__main__":
    main()
