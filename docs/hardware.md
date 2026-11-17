# Power Supply

## 1. Basic Specifications

- **Input Voltage:** 9–36V DC
- **Output Voltage:** 3.3V DC
- **Maximum Output Current:** 1.5A
- **Output Power:** 4.95W
- **Power Converter:** Synchronous Buck Regulator
- **Regulator:** Texas Instruments LMR36520ADDAR

## 2. Protection Requirements

- Input Fuse / Overcurrent Protection
- Transient Voltage Protection (TVS)
- Reverse Polarity Protection

## 3. Input Connector and Protection Components

### J1 — 2-Pin Screw Terminal Block

- **Manufacturer:** KANGNEX (Ningbo Kangnex Electric)
- **Part Number:** WJ500V-5.08-2P
- **Connector Type:** 2-Position Screw Terminal Block
- **Pitch:** 5.08mm
- **Rated Voltage:** 250V
- **Rated Current:** 18A
- **Wire Gauge:** 14–30 AWG / up to 2.5mm²
- **Operating Temperature:** -40°C to +105°C
- **Mounting:** Through-Hole
- **LCSC Part Number:** C8465
- **LCSC:** https://www.lcsc.com/product-detail/C8465.html

### F1 — Fuse

- **Manufacturer:** Littelfuse
- **Part Number:** 046801.5NRHF
- **Series:** 468 Slo-Blo
- **Current Rating:** 1.5A
- **Voltage Rating:** 63V DC
- **Fuse Type:** Time-Delay (Slow-Blow)
- **Package:** 1206 (3216 Metric)
- **Interrupt Rating:** 50A
- **Melting I²t:** 0.288 A²s
- **Operating Temperature:** -55°C to +90°C
- **LCSC Part Number:** C151143
- **LCSC:** https://www.lcsc.com/product-detail/C151143.html

### D1 — TVS Diode

- **Manufacturer:** Littelfuse
- **Part Number:** SMCJ40A
- **Type:** Unidirectional TVS
- **Reverse Standoff Voltage (VRWM):** 40V
- **Breakdown Voltage (VBR):** 44.4–49.1V
- **Clamping Voltage (VC):** 64.5V
- **Peak Pulse Power (PPPM):** 1500W
- **Peak Pulse Current (IPP):** 23.3A
- **Pulse Waveform:** 10/1000µs
- **Package:** SMC (DO-214AB)
- **Operating Junction Temperature:** -55°C to +150°C
- **LCSC Part Number:** C224052
- **LCSC:** https://www.lcsc.com/product-detail/C224052.html

### D2 — Reverse Polarity Protection (RPP)

- **Manufacturer:** STMicroelectronics
- **Part Number:** STPS2H100A
- **Type:** Schottky Rectifier Diode
- **Repetitive Peak Reverse Voltage (VRRM):** 100V
- **Average Forward Current (IF(AV)):** 2A
- **Maximum Forward Voltage (VF):** 0.79V at 2A
- **Non-Repetitive Peak Forward Surge Current (IFSM):** 75A
- **Maximum Junction Temperature:** +175°C
- **Package:** SMA (DO-214AC)
- **LCSC Part Number:** C81548
- **LCSC:** https://www.lcsc.com/product-detail/C81548.html

## 4. Buck Regulator — LMR36520

**TI WEBENCH Design:**  
https://webench.ti.com/appinfo/webench/scripts/SDP.cgi?ID=166BE3E204B8B8AB

### U1 — Buck Regulator IC

- **Manufacturer:** Texas Instruments
- **Part Number:** LMR36520ADDAR
- **Input Voltage:** 4.2–65V
- **Output Current:** 2A
- **Package:** HSOIC-8 (DDA)
- **LCSC Part Number:** C2879422
- **LCSC:** https://www.lcsc.com/product-detail/C2879422.html

### L1 — Power Inductor

- **Manufacturer:** PROD Tech
- **Part Number:** PSPMAA1040-100M-ANP
- **Inductance:** 10µH
- **Current Rating:** 7A
- **Saturation Current:** 10A
- **DC Resistance (DCR):** 33mΩ
- **Tolerance:** ±20%
- **Package:** SMD 11 × 10mm
- **LCSC Part Number:** C2983105
- **LCSC:** https://www.lcsc.com/product-detail/C2983105.html

### C1 — Input Capacitor

- **Manufacturer:** IHHEC
- **Part Number:** C2220X106K101T
- **Capacitance:** 10µF
- **Voltage Rating:** 100V
- **Dielectric:** X7R
- **Tolerance:** ±10%
- **Package:** 2220
- **LCSC Part Number:** C556893
- **LCSC:** https://www.lcsc.com/product-detail/C556893.html

### C2 — Input Bypass Capacitor

- **Manufacturer:** YAGEO
- **Part Number:** CC0805KKX7R0BB224
- **Capacitance:** 220nF
- **Voltage Rating:** 100V
- **Dielectric:** X7R
- **Tolerance:** ±10%
- **Package:** 0805
- **LCSC Part Number:** C513710
- **LCSC:** https://www.lcsc.com/product-detail/C513710.html

### C3 — VCC Capacitor

- **Manufacturer:** CCTC
- **Part Number:** TCC0402X7R105K160AT
- **Capacitance:** 1µF
- **Voltage Rating:** 16V
- **Dielectric:** X7R
- **Tolerance:** ±10%
- **Package:** 0402
- **LCSC Part Number:** C49210445
- **LCSC:** https://www.lcsc.com/product-detail/C49210445.html

### C4 — Bootstrap Capacitor

- **Manufacturer:** CCTC
- **Part Number:** TCC0402X7R104K160AT
- **Capacitance:** 100nF
- **Voltage Rating:** 16V
- **Dielectric:** X7R
- **Tolerance:** ±10%
- **Package:** 0402
- **LCSC Part Number:** C392963
- **LCSC:** https://www.lcsc.com/product-detail/C392963.html

### C5, C6 — Output Capacitors

- **Manufacturer:** Murata
- **Part Number:** GRM32ER60J107ME20L
- **Capacitance:** 100µF each
- **Total Nominal Capacitance:** 200µF
- **Voltage Rating:** 6.3V
- **Dielectric:** X5R
- **Tolerance:** ±20%
- **Package:** 1210
- **Quantity:** 2
- **LCSC Part Number:** C88154
- **LCSC:** https://www.lcsc.com/product-detail/C88154.html

### R1 — Power Good Pull-Up (RPG)

- **Manufacturer:** Vishay
- **Part Number:** CRCW0402100KFKED
- **Resistance:** 100kΩ
- **Tolerance:** ±1%
- **Power Rating:** 63mW
- **Package:** 0402
- **LCSC Part Number:** C481918
- **LCSC:** https://www.lcsc.com/product-detail/C481918.html

### R2 — Feedback Upper Resistor (RFBT)

- **Manufacturer:** Vishay
- **Part Number:** CRCW0402100KFKED
- **Resistance:** 100kΩ
- **Tolerance:** ±1%
- **Power Rating:** 63mW
- **Package:** 0402
- **LCSC Part Number:** C481918
- **LCSC:** https://www.lcsc.com/product-detail/C481918.html

### R3 — Feedback Lower Resistor (RFBB)

- **Manufacturer:** YAGEO
- **Part Number:** AF0402FR-0743K2L
- **Resistance:** 43.2kΩ
- **Tolerance:** ±1%
- **Power Rating:** 62.5mW
- **Package:** 0402
- **LCSC Part Number:** C2097969
- **LCSC:** https://www.lcsc.com/product-detail/C2097969.html
