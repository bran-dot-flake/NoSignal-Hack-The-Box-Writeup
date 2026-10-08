<img src="images/sherlock.png" alt="Hack The Box Sherlock badge" width="110" />

# NoSignal - Sherlock Writeup

![Hack The Box](https://img.shields.io/badge/Hack%20The%20Box-Sherlock-9FEF00?logo=hackthebox&logoColor=black)
![Difficulty](https://img.shields.io/badge/Difficulty-Hard-D7263D)
![Category](https://img.shields.io/badge/Category-DFIR-E74C3C)

*A CCTV network-forensics investigation covering service reconnaissance, camera authentication attempts, and an interrupted video stream.*

by: Brandon Chaney

## Overview

This Sherlock starts by telling us that CCTV cameras were the subject of some recon and were showing strange behavior afterward, including stream interruptions and restarts. I’m given a PCAP file, `CCTV.pcap`, and tasked with identifying the attacker, determining what happened to the cameras, and constructing a timeline.

> Using TShark to look through TCP, HTTP, RTSP, and RTP traffic, I worked through the reconnaissance, camera access, login attempts, and video interruption to piece together what happened.

## Affected Systems

| IP | Observed role | Evidence |
| --- | --- | --- |
| `192.168.50.200` | Attacker / scanner | Multiple TCP SYN probes, RTSP request, HTTP authentication attempts |
| `192.168.50.12` | Targeted CCTV camera (CAM2) | RTSP `554`, HTTP `80`, RTP video, authentication and administrative responses |
| `192.168.50.11` | Other CCTV camera | RTP stream sent to `.5`; no direct attacker access established here |
| `192.168.50.5` | Video receiver / likely recorder | Large RTP transfers from both cameras; also received limited probes from attacker |
| `192.168.50.100` | Other network host | Low-volume traffic; role not established |

![Affected systems diagram](images/affected-systems.svg)

## Reconnaissance: Finding the Attacker

To start, the IP of the attacker must be found. I utilized TShark to look for recon activity by seeing who sent the most SYN packets, a common indicator of port scanning. The IP `192.168.50.200` stands out the most due to sending an abnormal amount of these packets.

```bash
tshark -r CCTV.pcap \
-Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
-T fields -e ip.src | sort | uniq -c | sort -nr
```

```text
21 192.168.50.200
 3 192.168.50.5
 1 192.168.50.100
```

Further evidence that `.200` was responsible for the recon came from looking at the connections being made. It appears the attacker probed `192.168.50.12` (main target) and also `192.168.50.5`. Looking at the destination ports, we can see what services they were checking:

```bash
tshark -r CCTV.pcap \
-Y "ip.src == 192.168.50.200 && tcp.flags.syn == 1 && tcp.flags.ack == 0" \
-T fields -e ip.src -e ip.dst -e tcp.dstport
```

```text
192.168.50.200  192.168.50.12  21
192.168.50.200  192.168.50.12  22
192.168.50.200  192.168.50.12  23
192.168.50.200  192.168.50.12  80
192.168.50.200  192.168.50.12  445
192.168.50.200  192.168.50.12  554
192.168.50.200  192.168.50.12  8080
192.168.50.200  192.168.50.5   3306
```

From these connections, it looks like FTP, SSH, Telnet, web interfaces, SMB, and RTSP camera streaming (port `554`) were enumerated. I counted the distinct ports to see how broad the scan was:

```bash
tshark -r CCTV.pcap \
-Y "ip.src == 192.168.50.200 && tcp.flags.syn == 1 && tcp.flags.ack == 0" \
-T fields -e tcp.dstport | sort -n | uniq | wc -l
# 16
```

I also checked IPv4 conversations. Despite making all those port probes, there was not much data being exchanged by the attacking IP—about **11 kB** with `.12` and **540 bytes** with `.5`. Compare this with the large transfers between the cameras and `.5`, which make more sense as ongoing video traffic.

```bash
tshark -r CCTV.pcap -q -z conv,ip
```

That small amount of data on its own doesn't prove a scan, but combined with the number of distinct ports being probed, `.200` is the clear suspect.

## Direct RTSP Access & Authentication Challenge

Next, I checked whether the attacker directly accessed one of the cameras through RTSP rather than just scanning port `554`. Sure enough, there is a `DESCRIBE` request directed at `192.168.50.12`. The camera responded with `401 Unauthorized`, so further investigation was needed.

```bash
tshark -r CCTV.pcap \
-d tcp.port==554,rtsp \
-Y "rtsp && ip.addr == 192.168.50.200"
```

```text
54447  696.973114  192.168.50.200 → 192.168.50.12  RTSP  DESCRIBE rtsp://192.168.50.12:554/Streaming/Channels/101 RTSP/1.0
54449  696.999937  192.168.50.12 → 192.168.50.200  RTSP  Reply: RTSP/1.0 401 Unauthorized
```

We can see this happened around 697 seconds from the beginning of the capture. To get the actual timestamp, I pulled the `frame.time` field:

```bash
tshark -r CCTV.pcap \
-d tcp.port==554,rtsp \
-Y "ip.src == 192.168.50.200 && rtsp.request" \
-T fields -e frame.number -e frame.time -e rtsp.method
```

```text
54447  Mar 12, 2026 02:31:37.045849000 UTC  DESCRIBE
```

As for the authentication mechanism, I used `grep` to grab the `WWW-Authenticate` header from the camera response:

```bash
tshark -r CCTV.pcap \
-d tcp.port==554,rtsp \
-Y "ip.src == 192.168.50.12 && rtsp" \
-V | grep -i "WWW-Authenticate"
```

```text
WWW-Authenticate: Digest realm="IP Camera(CAM2)", nonce="98ab01a7f0", qop="auth"
```

This showed **Digest authentication** was being used, with `IP Camera(CAM2)` listed in the realm. The RTSP request itself did not give us the password, so I moved on to the HTTP traffic.

## HTTP Credential Guessing & Successful Login

Brute-force login attempts were later observed. I searched the attacker’s TCP payloads for strings relevant to authentication, and found several combinations being sent to `/ISAPI/Security/userCheck`:

```bash
tshark -r CCTV.pcap \
-Y "ip.src == 192.168.50.200 && tcp.len > 0" \
-T fields -e tcp.payload | xxd -r -p | strings \
| grep -iE "password|passwd|username|authorization"
```

The XML request bodies exposed the attempted combinations:

| Username | Password | Observed result |
| --- | --- | --- |
| `admin` | `12345` | `403 Forbidden` |
| `admin` | `password` | `403 Forbidden` |
| `admin` | `camera` | `403 Forbidden` |
| `admin` | `hikvision` | `403 Forbidden` |
| `root` | `root` | `403 Forbidden` |
| `service` | `service` | `403 Forbidden` |
| **`admin`** | **`admin`** | **`200 OK`** |

For example, the final submitted credentials appeared as:

```xml
<UserCheck><userName>admin</userName><password>admin</password></UserCheck>
```

The final combination before a request for `/ISAPI/System/status` was `admin:admin`. I checked the responses to verify it: several `403 Forbidden` messages appeared before an HTTP `200 OK` at 02:31:40 UTC. The **first POST at frame `54462`** also marks where the attacker moved from reconnaissance into exploitation.

```bash
tshark -r CCTV.pcap \
-Y 'http.request || http.response' \
-T fields -e frame.number -e frame.time -e ip.src -e ip.dst \
-e http.request.method -e http.request.uri -e http.response.code
```

```text
54486  02:31:40.395100 UTC  192.168.50.200 → 192.168.50.12  POST /ISAPI/Security/userCheck
54488  02:31:40.437751 UTC  192.168.50.12 → 192.168.50.200  200
54490  02:31:40.816757 UTC  192.168.50.200 → 192.168.50.12  GET /ISAPI/System/status
54492  02:31:40.852882 UTC  192.168.50.12 → 192.168.50.200  200
```

## Post-Authentication Camera Activity

Here are the specific requests following the successful login. It is also evident that the attacker began interacting with the system: accessing the streaming channel, issuing a recording command, and requesting a system restart, like we heard about in the scenario.

| Frame | Request | Response |
| --- | --- | --- |
| `54490` | `GET /ISAPI/System/status` | `200 OK` |
| `54494` | `GET /ISAPI/Streaming/channels/101/status` | `200 OK` |
| `54498` | `PUT /ISAPI/ContentMgmt/record/control/manual/start/tracks/101` | `200 OK` |
| `54502` | `PUT /ISAPI/System/reboot` | Request observed; response should be assessed separately |

The reboot request is especially interesting given the strange camera behavior reported at the start. The capture shows the request being sent, although the request alone does not establish its outcome.

## RTP Video Traffic & Stream Interruption

The **RTP** protocol carries the video packets. This is separate from RTSP, which handles the stream controls. We can see RTP traffic coming from the cameras and going to `.5`. I also checked the payload type for camera `.12`:

```bash
tshark -r CCTV.pcap -Y "rtp" \
-T fields -e ip.src -e ip.dst -e rtp.seq | head -15

tshark -r CCTV.pcap \
-Y "rtp && ip.src == 192.168.50.12" \
-T fields -e rtp.p_type | sort -u
# 96
```

The RTP payload type is `96`, but that means it is dynamic, so it does not identify the codec by itself. I used `grep` on the RTSP session information to see what the cameras agreed to use:

```bash
tshark -r CCTV.pcap -d tcp.port==554,rtsp \
-Y "rtsp" -V | grep -iE "H264|H265|HEVC|a=rtpmap"
```

```text
a=rtpmap:96 H264/90000
```

That confirmed **H.264**, with a 90,000 Hz RTP clock. Next I looked at the SSRC fields (the 32-bit identifiers for RTP sources) from `192.168.50.12` and found two different values. Since an SSRC can change when a stream restarts, I was curious whether this tied into the attacker’s activity.

```bash
tshark -r CCTV.pcap \
-Y "rtp && ip.src == 192.168.50.12" \
-T fields -e frame.time_relative -e rtp.ssrc \
| awk '!seen[$2]++'
```

```text
703.660879000   0x1de257b2
1402.486047000  0xa6251f2d
```

The first SSRC appears earlier in the capture, and the second appears after the stream interruption. To finish the stream timeline, I checked the last packet of the original stream and the first packet of the resumed stream:

```bash
tshark -r CCTV.pcap \
-Y "rtp.ssrc == 0x1de257b2 && ip.src == 192.168.50.12" \
-T fields -e frame.number -e frame.time_relative | tail -1

tshark -r CCTV.pcap \
-Y "rtp.ssrc == 0xa6251f2d && ip.src == 192.168.50.12" \
-T fields -e frame.number -e frame.time_relative | head -1
```

```text
108636  1393.510585000  # Last original RTP packet
108664  1402.486047000  # First resumed RTP packet
```

Between them, frame `108637` contains an RTSP `TEARDOWN`. The session then reconnects and sends `OPTIONS`, `DESCRIBE`, `SETUP`, and `PLAY`, followed by frame `108664` starting the new RTP stream with SSRC `0xa6251f2d`.

![RTP interruption and resumed session](images/stream-interruption.svg)

### Measuring the Interruption

To find how long the video traffic was interrupted, I calculated the time differences between **consecutive RTP packets** across the capture and pulled the largest gap. Rather than relying on an application log, this uses packet timing to find the outage.

```bash
tshark -r CCTV.pcap -Y "rtp" -T fields -e frame.time_relative \
| awk 'NR>1 {gap=$1-prev; if(gap>max) max=gap} {prev=$1} END {print max}'
```

```text
11.5275
```

The largest observed RTP gap was **11.5275 seconds**. The resumed stream from camera `.12` is identifiable at **frame `108664`**, where the SSRC changes to `0xa6251f2d`.

## RTSP Device Identification

The last thing I investigated was the banner showing the device type. I started by looking at the RTSP server responses to see if they gave away any device information, which they did:

```bash
tshark -r CCTV.pcap -Y "frame.number == 54449" -V \
| grep -i "Server:"
```

```text
Server: Hikvision-IP-Camera/5.5.82
```

This identifies a **Hikvision IP camera** reporting `5.5.82`. Interestingly, there were two different versions in the capture, so I also checked a response following the interruption:

```bash
tshark -r CCTV.pcap -Y "frame.number == 108650" -V \
| grep -i "Server:"
```

```text
Server: Hikvision-IP-Camera/5.5.80
```

The `.82` banner appeared before the stream restart, while `.80` appeared afterward. I would not call that a confirmed firmware downgrade, but it is an interesting change in what the camera reports.

## Attack Timeline

![NoSignal attack timeline](images/timeline.svg)

## Key Findings

- `192.168.50.200` scanned **16 distinct destination ports** and probed both `.12` and `.5`.
- `192.168.50.12` received an RTSP `DESCRIBE` on TCP `554` and challenged the attacker with **Digest authentication**.
- The attacker performed HTTP credential guessing; **`admin:admin`** was accepted after several `403` responses. The first POST is **frame `54462`**.
- With access, the attacker queried camera status, issued a recording command, and requested a reboot.
- RTP payload type **96** mapped to **H.264**. CAM2's SSRC changed from `0x1de257b2` to `0xa6251f2d` after an RTSP teardown and reconnect.
- The largest gap between consecutive RTP packets was **11.5275 seconds**. Camera `.12` resumed with a new SSRC at frame `108664`.
- RTSP banners reported `Hikvision-IP-Camera/5.5.82` initially and `Hikvision-IP-Camera/5.5.80` later. That difference is an observation, not a verified firmware change.

## Resources

- [RFC 2326 — Real Time Streaming Protocol (RTSP)](https://datatracker.ietf.org/doc/html/rfc2326)
- [RFC 3550 — RTP: A Transport Protocol for Real-Time Applications](https://datatracker.ietf.org/doc/html/rfc3550)
- [RFC 6184 — RTP Payload Format for H.264 Video](https://datatracker.ietf.org/doc/html/rfc6184)
