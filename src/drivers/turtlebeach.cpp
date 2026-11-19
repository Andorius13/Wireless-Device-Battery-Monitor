// Turtle Beach Stealth 700 Gen 3 headsets (VID 10F5) on the USB transmitter or the headset's own USB cable.
// Ported from HaloBattery (github.com/HeyOkay/HaloBattery, providers/turtlebeach.py, MIT), whose Stealth 700
// Gen 3 path comes from @PaulRichez's reverse engineering of Swarm II (github.com/PaulRichez/
// halobattery-stealth700, docs/protocol.md, MIT; tested on the Stealth 700X Gen 3 transmitter 10F5:2251, and
// the headset's cable 10F5:2253 answers the same request). lykosapps/Neap (FINDINGS.md, GPL-3.0; only its
// findings are used, no code) lists the Stealth 700 PC, PlayStation and Xbox versions in Swarm II's catalogue as
// the same Airoha chip family, with the same control channel.
//   Vendor collection FF13:0001 on interface 3. Host -> device: 62-byte output report 06, `06 <len16 LE> <RACE
//   bytes>`; device -> host: input report 07 framed `07 <len> 00 <payload>`, fetched with GetInputReport.
//   1. RACE 0x9942, enable the chip's CoAP client: 05 5A 02 00 42 99 (what Swarm II sends on every poll).
//   2. RACE 0x9902 carrying a CoAP GET /GSI: 05 5A 0A 00 02 99 40 01 00 01 B3 47 53 49.
//   The answer is a JSON document {"OR":"GSI","KVP":{..., "240":"<percent>", ...}}, split across reports.
// Nothing else is sent, and nothing on the headset is changed. Charging is not reported: key 250 stayed "0"
// with the cable in on the Stealth 700 Gen 3 (HaloBattery #211), so it is left out.
// 10F5:2262 ("Stealth 700PC Gen 3", issue #1413) has the same FF13:0001 62-byte collection on interface 3;
// it is the PC version of the same headset and is read the same way (untested on hardware). The unconfirmed
// transmitter 10F5:2250 and the other models of the family (Stealth 600 Gen 3, Atlas Air) are not enabled here.
//
// Stealth Pro II (10F5:2287 "Stealth Pro II PC" transmitter, tested here; 10F5:229B transmitter and 10F5:229E
// headset cable from HaloBattery #173) has the same FF13:0001 collection but answers Swarm II's own record asks
// instead of the CoAP tunnel: first the "SInf" session opener, then the "GSI" ask, both byte for byte from
// HaloBattery's capture. The same GSI document comes back (240 = percent, 250 = charging on this model), split
// into ~6 ms-apart frames that GetInputReport only sees while they are current, so the replies are polled
// back to back and each frame is scanned on its own (on the 2287 the "240" pair always sits inside one frame).
// Only these two record asks are ever sent; nothing on the headset is changed.
#include "drivers.h"

#include <cwctype>
#include <string>

namespace {

constexpr USHORT kVid = 0x10F5;
struct Model { USHORT pid; bool cable; };
// The transmitters first: the same headset is listed once, through whichever answers first.
const Model kModels[] = { { 0x2251, false },  // Stealth 700X Gen 3 transmitter (tested in HaloBattery)
                          { 0x2262, false },  // Stealth 700PC Gen 3 transmitter (#1413)
                          { 0x2253, true } };  // the headset on its own USB cable (tested in HaloBattery)
const Model kProModels[] = { { 0x2287, false },  // Stealth Pro II PC transmitter (tested)
                             { 0x229B, false },  // Stealth Pro II transmitter (HaloBattery #173)
                             { 0x229E, true } };  // Stealth Pro II on its own USB cable (HaloBattery)

// Swarm II's "SInf" session opener and "GSI" record ask (HaloBattery, capture packets 150 and 616).
const BYTE kAskSinf[] = { 0x06, 0x18, 0x00, 0x05, 0x5A, 0x14, 0x00, 0x02, 0x99, 0x48, 0x01, 0xC0, 0x4A, 0x01,
                          0, 0, 0, 0, 0, 0, 0, 0x61, 0x00, 0x53, 0x49, 0x6E, 0x66 };
const BYTE kAskGsi[] = { 0x06, 0x18, 0x00, 0x05, 0x5A, 0x14, 0x00, 0x02, 0x99, 0x48, 0x01, 0x44, 0x14, 0x04,
                         0, 0, 0, 0, 0, 0, 0, 0x61, 0x00, 0x53, 0x47, 0x53, 0x49 };

bool Send(HidDev& d, std::initializer_list<BYTE> race) {
    std::vector<BYTE> buf(62, 0);
    buf[0] = 0x06;
    buf[1] = (BYTE)race.size();
    buf[2] = 0;
    size_t i = 3;
    for (BYTE b : race) buf[i++] = b;
    return d.Write(buf);
}

void Drain(HidDev& d, int n) {
    std::vector<BYTE> r;
    for (int i = 0; i < n; i++) d.GetInputReport(0x07, r);
}

// The newest "240" (battery percent) of a GSI document in the payload stream, or -1.
int FindLevel(const std::string& s) {
    if (s.find("\"GSI\"") == std::string::npos) return -1;
    int level = -1;
    const std::string key = "\"240\":\"";
    for (size_t p = s.find(key); p != std::string::npos; p = s.find(key, p + 1)) {
        size_t q = p + key.size();
        int v = 0, digits = 0;
        while (q < s.size() && s[q] >= '0' && s[q] <= '9' && digits < 4) v = v * 10 + (s[q++] - '0'), digits++;
        if (digits > 0 && q < s.size() && s[q] == '"' && v <= 100) level = v;
    }
    return level;
}

int ReadLevel(const HidColl& c) {
    HidDev d;
    if (!d.Open(c)) return -1;
    Drain(d, 5);
    if (!Send(d, { 0x05, 0x5A, 0x02, 0x00, 0x42, 0x99 })) return -1;  // enable the CoAP client
    Sleep(300);  // the chip needs a moment after the client is enabled
    Drain(d, 5);
    if (!Send(d, { 0x05, 0x5A, 0x0A, 0x00, 0x02, 0x99, 0x40, 0x01, 0x00, 0x01, 0xB3, 'G', 'S', 'I' })) return -1;
    std::string payload;
    for (int i = 0; i < 30; i++) {
        Sleep(30);
        std::vector<BYTE> r;
        if (!d.GetInputReport(0x07, r) || r.size() < 3 || r[0] != 0x07) continue;
        size_t n = r[1];
        if (n > r.size() - 3) n = r.size() - 3;
        payload.append((const char*)r.data() + 3, n);
        int level = FindLevel(payload);
        if (level >= 0) return level;
    }
    return -1;
}

// The number of `"<key>":"<digits>"` inside one frame's text, or -1 when the pair is not complete there.
int FrameValue(const std::string& s, const char* key) {
    const std::string k = std::string("\"") + key + "\":\"";
    size_t p = s.find(k);
    if (p == std::string::npos) return -1;
    size_t q = p + k.size();
    int v = 0, digits = 0;
    while (q < s.size() && s[q] >= '0' && s[q] <= '9' && digits < 4) v = v * 10 + (s[q++] - '0'), digits++;
    return (digits > 0 && q < s.size() && s[q] == '"') ? v : -1;
}

// Stealth Pro II: SInf opener, then the GSI ask; the replies are polled back to back until the level shows up.
int ReadProLevel(const HidColl& c, bool& charging) {
    HidDev d;
    if (!d.Open(c)) return -1;
    charging = false;
    // The SInf dump may already carry the level; the GSI answer took up to ~1.1 s on the 2287.
    const struct { const BYTE* data; size_t len; ULONGLONG waitMs; } asks[] = {
        { kAskSinf, sizeof kAskSinf, 800 }, { kAskGsi, sizeof kAskGsi, 2500 } };
    for (const auto& ask : asks) {
        std::vector<BYTE> buf(ask.data, ask.data + ask.len);
        buf.resize(62, 0);
        if (!d.Write(buf)) return -1;
        const ULONGLONG end = GetTickCount64() + ask.waitMs;
        while (GetTickCount64() < end) {
            std::vector<BYTE> r;
            if (!d.GetInputReport(0x07, r) || r.size() < 4 || r[0] != 0x07 || r[1] == 0) continue;
            size_t n = r[1];
            if (n > r.size() - 3) n = r.size() - 3;
            std::string frame((const char*)r.data() + 3, n);
            int level = FrameValue(frame, "240");
            if (level >= 0 && level <= 100) {
                charging = FrameValue(frame, "250") == 1;
                return level;
            }
        }
    }
    return -1;
}

std::wstring ModelName(const HidColl& c, const wchar_t* fallback) {
    std::wstring product = HidProduct(c);  // e.g. "Stealth 700X Gen 3"
    if (product.empty()) return fallback;
    std::wstring lower = product;
    for (auto& ch : lower) ch = (wchar_t)towlower(ch);
    if (lower.compare(0, 12, L"turtle beach") != 0) product = L"Turtle Beach " + product;
    return product;
}

// One headset family: transmitter(s) and cable are one entry, read through whichever answers first.
template <size_t N>
void PollFamily(PollContext& ctx, const Model (&models)[N], bool pro) {
    const HidColl* found = nullptr;
    const Model* foundModel = nullptr;
    int level = -1;
    bool charging = false;
    for (const Model& m : models) {
        if (ctx.IsClaimed(kVid, m.pid)) continue;
        auto colls = ctx.Find(kVid, m.pid, [](const HidColl& c) {
            return c.page() == 0xFF13 && c.usage() == 0x0001 && c.inLen() > 0 && c.outLen() > 0;
        });
        if (colls.empty()) continue;
        if (!found) found = colls[0], foundModel = &m;
        level = pro ? ReadProLevel(*colls[0], charging) : ReadLevel(*colls[0]);
        if (level >= 0) {
            found = colls[0];
            foundModel = &m;
            break;
        }
    }
    if (!found) return;
    DeviceStatus s;
    s.key = pro ? L"turtlebeach:stealthpro2" : L"turtlebeach:stealth700";
    s.name = ModelName(*found, pro ? L"Turtle Beach Stealth Pro II" : L"Turtle Beach Stealth 700 Gen 3");
    s.kind = DeviceKind::Headset;
    s.via = foundModel->cable ? L"USB cable" : L"2.4 GHz transmitter";
    s.graceSec = 300;
    if (level < 0) {
        s.asleep = true;  // no record (headset off, or Swarm II holding the channel): keep the last value
    } else {
        s.percent = level;
        s.charging = charging;  // key 250 is the charging flag on the Pro II only (always false for the 700)
    }
    ctx.Add(s, kVid, foundModel->pid);
    for (const Model& o : models) ctx.Claim(kVid, o.pid);  // one entry for the headset
}

}  // namespace

void PollTurtleBeach(PollContext& ctx) {
    PollFamily(ctx, kModels, false);
    PollFamily(ctx, kProModels, true);
}
