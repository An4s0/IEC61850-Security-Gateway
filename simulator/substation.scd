<?xml version="1.0" encoding="UTF-8"?>
<!--
  IEC 61850 Substation Configuration Description (SCD)
  Edition: IEC 61850-6 Edition 2.1 (2007B release 4)
  Purpose: Single Source of Truth for IEC 61850 Security Gateway / IDS
  Substation: SUB01 (132/33 kV)
  Created for: IEC 61850 Security Gateway project
-->
<SCL xmlns="http://www.iec.ch/61850/2003/SCL"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" version="2007" revision="B" release="4">

  <Header id="SUB01_SCD" version="1.0.0" revision="" toolID="IEC61850_SecurityGateway" nameStructure="IEDName">
    <History>
      <Hitem version="1.0.0" revision="" when="2026-08-17T00:00:00Z" who="SecurityGateway" what="Initial SCD creation" why="Single source of truth for IEC 61850 Security Gateway / IDS baseline"/>
    </History>
  </Header>

  <!-- ============================================================ -->
  <!-- SUBSTATION TOPOLOGY                                          -->
  <!-- ============================================================ -->
  <Substation name="SUB01" desc="132/33 kV Distribution Substation">
    <!-- Station-level logical node binding -->
    <LNode iedName="IED5_StationCtrl" ldInst="STCTL" lnClass="GGIO" lnInst="1"/>

    <!-- ======== 132 kV Voltage Level ======== -->
    <VoltageLevel name="E1" desc="132 kV" nomFreq="50" numPhases="3">
      <Voltage unit="V" multiplier="k">132</Voltage>

      <!-- Busbar Bay -->
      <Bay name="BUSBAR" desc="132 kV Busbar Section">
        <ConnectivityNode name="BB1" pathName="SUB01/E1/BUSBAR/BB1"/>
      </Bay>

      <!-- Bay Q01: Breaker 52A + Protection -->
      <Bay name="Q01" desc="132 kV Feeder Bay - Breaker 52A">
        <!-- Circuit Breaker 52A -->
        <ConductingEquipment name="QA1" type="CBR" desc="Circuit Breaker 52A">
          <Terminal name="T1" connectivityNode="SUB01/E1/Q01/N1" substationName="SUB01" voltageLevelName="E1" bayName="Q01" cNodeName="N1"/>
          <Terminal name="T2" connectivityNode="SUB01/E1/Q01/N2" substationName="SUB01" voltageLevelName="E1" bayName="Q01" cNodeName="N2"/>
          <LNode iedName="IED1_Breaker52A" ldInst="CTRL" lnClass="XCBR" lnInst="1"/>
          <LNode iedName="IED1_Breaker52A" ldInst="CTRL" lnClass="CSWI" lnInst="1"/>
        </ConductingEquipment>
        <!-- Bus Disconnector -->
        <ConductingEquipment name="QB1" type="DIS" desc="Bus Disconnector">
          <Terminal name="T1" connectivityNode="SUB01/E1/BUSBAR/BB1" substationName="SUB01" voltageLevelName="E1" bayName="BUSBAR" cNodeName="BB1"/>
          <Terminal name="T2" connectivityNode="SUB01/E1/Q01/N1" substationName="SUB01" voltageLevelName="E1" bayName="Q01" cNodeName="N1"/>
        </ConductingEquipment>
        <!-- Line Disconnector -->
        <ConductingEquipment name="QB2" type="DIS" desc="Line Disconnector">
          <Terminal name="T1" connectivityNode="SUB01/E1/Q01/N2" substationName="SUB01" voltageLevelName="E1" bayName="Q01" cNodeName="N2"/>
          <Terminal name="T2" connectivityNode="SUB01/E1/Q01/L1" substationName="SUB01" voltageLevelName="E1" bayName="Q01" cNodeName="L1"/>
        </ConductingEquipment>
        <!-- Earth Switch -->
        <ConductingEquipment name="QC1" type="DIS" desc="Line Earth Switch">
          <Terminal name="T1" connectivityNode="SUB01/E1/Q01/L1" substationName="SUB01" voltageLevelName="E1" bayName="Q01" cNodeName="L1"/>
        </ConductingEquipment>
        <!-- Current Transformer (132 kV bay) -->
        <ConductingEquipment name="CT1" type="CTR" desc="Current Transformer 132 kV">
          <Terminal name="T1" connectivityNode="SUB01/E1/Q01/N2" substationName="SUB01" voltageLevelName="E1" bayName="Q01" cNodeName="N2"/>
        </ConductingEquipment>
        <!-- Voltage Transformer (132 kV bay) -->
        <ConductingEquipment name="VT1" type="VTR" desc="Voltage Transformer 132 kV">
          <Terminal name="T1" connectivityNode="SUB01/E1/Q01/N1" substationName="SUB01" voltageLevelName="E1" bayName="Q01" cNodeName="N1"/>
        </ConductingEquipment>
        <!-- Protection LNode bindings -->
        <LNode iedName="IED2_Protection" ldInst="PROT" lnClass="PTOC" lnInst="1"/>
        <LNode iedName="IED2_Protection" ldInst="PROT" lnClass="PTRC" lnInst="1"/>
        <LNode iedName="IED1_Breaker52A" ldInst="CTRL" lnClass="CILO" lnInst="1"/>
        <ConnectivityNode name="N1" pathName="SUB01/E1/Q01/N1"/>
        <ConnectivityNode name="N2" pathName="SUB01/E1/Q01/N2"/>
        <ConnectivityNode name="L1" pathName="SUB01/E1/Q01/L1"/>
      </Bay>

      <!-- Bay Q02: Bay Control -->
      <Bay name="Q02" desc="132 kV Bay Control">
        <LNode iedName="IED3_BayControl" ldInst="BAYCTL" lnClass="CSWI" lnInst="1"/>
        <LNode iedName="IED3_BayControl" ldInst="BAYCTL" lnClass="CILO" lnInst="1"/>
        <LNode iedName="IED3_BayControl" ldInst="BAYCTL" lnClass="GGIO" lnInst="1"/>
      </Bay>
    </VoltageLevel>

    <!-- ======== 33 kV Voltage Level ======== -->
    <VoltageLevel name="E2" desc="33 kV" nomFreq="50" numPhases="3">
      <Voltage unit="V" multiplier="k">33</Voltage>

      <!-- Busbar Bay -->
      <Bay name="BUSBAR2" desc="33 kV Busbar Section">
        <ConnectivityNode name="BB2" pathName="SUB01/E2/BUSBAR2/BB2"/>
      </Bay>

      <!-- Bay Q03: Measurement / Merging Unit -->
      <Bay name="Q03" desc="33 kV Measurement Bay - Merging Unit">
        <ConductingEquipment name="CT2" type="CTR" desc="Current Transformer 33 kV (3-phase)">
          <Terminal name="T1" connectivityNode="SUB01/E2/Q03/M1" substationName="SUB01" voltageLevelName="E2" bayName="Q03" cNodeName="M1"/>
          <LNode iedName="IED4_MergingUnit" ldInst="MU" lnClass="TCTR" lnInst="1"/>
          <LNode iedName="IED4_MergingUnit" ldInst="MU" lnClass="TCTR" lnInst="2"/>
          <LNode iedName="IED4_MergingUnit" ldInst="MU" lnClass="TCTR" lnInst="3"/>
        </ConductingEquipment>
        <ConductingEquipment name="VT2" type="VTR" desc="Voltage Transformer 33 kV (3-phase)">
          <Terminal name="T1" connectivityNode="SUB01/E2/Q03/M1" substationName="SUB01" voltageLevelName="E2" bayName="Q03" cNodeName="M1"/>
          <LNode iedName="IED4_MergingUnit" ldInst="MU" lnClass="TVTR" lnInst="1"/>
          <LNode iedName="IED4_MergingUnit" ldInst="MU" lnClass="TVTR" lnInst="2"/>
          <LNode iedName="IED4_MergingUnit" ldInst="MU" lnClass="TVTR" lnInst="3"/>
        </ConductingEquipment>
        <LNode iedName="IED4_MergingUnit" ldInst="MU" lnClass="MMXU" lnInst="1"/>
        <ConnectivityNode name="M1" pathName="SUB01/E2/Q03/M1"/>
      </Bay>
    </VoltageLevel>
  </Substation>

  <!-- ============================================================ -->
  <!-- COMMUNICATION                                                -->
  <!-- ============================================================ -->
  <Communication>

    <!-- ======== Station Bus (MMS + GOOSE) ======== -->
    <SubNetwork name="StationBus" desc="132/33 kV Station Bus" type="8-MMS">

      <!-- IED1_Breaker52A on Station Bus -->
      <ConnectedAP iedName="IED1_Breaker52A" apName="S1">
        <Address>
          <P type="IP">192.168.10.11</P>
          <P type="IP-SUBNET">255.255.255.0</P>
          <P type="IP-GATEWAY">192.168.10.1</P>
          <P type="OSI-PSEL">00000001</P>
          <P type="OSI-SSEL">0001</P>
          <P type="OSI-TSEL">0001</P>
        </Address>
        <!-- GOOSE: Breaker Status (IED1 publishes) -->
        <GSE ldInst="CTRL" cbName="gcbBreakerStatus">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-01</P>
            <P type="APPID">0001</P>
            <P type="VLAN-ID">064</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
          <MinTime unit="s" multiplier="m">4</MinTime>
          <MaxTime unit="s" multiplier="m">1000</MaxTime>
        </GSE>
        <Private type="SecurityGateway-SourceMAC">00-30-A7-01-00-01</Private>
      </ConnectedAP>

      <!-- IED2_Protection on Station Bus -->
      <ConnectedAP iedName="IED2_Protection" apName="S1">
        <Address>
          <P type="IP">192.168.10.12</P>
          <P type="IP-SUBNET">255.255.255.0</P>
          <P type="IP-GATEWAY">192.168.10.1</P>
          <P type="OSI-PSEL">00000001</P>
          <P type="OSI-SSEL">0001</P>
          <P type="OSI-TSEL">0001</P>
        </Address>
        <!-- GOOSE: Trip Command (IED2 publishes) -->
        <GSE ldInst="PROT" cbName="gcbTripCommand">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-02</P>
            <P type="APPID">0002</P>
            <P type="VLAN-ID">064</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
          <MinTime unit="s" multiplier="m">2</MinTime>
          <MaxTime unit="s" multiplier="m">1000</MaxTime>
        </GSE>
        <!-- GOOSE: Protection Status (IED2 publishes) -->
        <GSE ldInst="PROT" cbName="gcbProtStatus">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-04</P>
            <P type="APPID">0004</P>
            <P type="VLAN-ID">064</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
          <MinTime unit="s" multiplier="m">4</MinTime>
          <MaxTime unit="s" multiplier="m">1000</MaxTime>
        </GSE>
        <Private type="SecurityGateway-SourceMAC">00-30-A7-01-00-02</Private>
      </ConnectedAP>

      <!-- IED3_BayControl on Station Bus -->
      <ConnectedAP iedName="IED3_BayControl" apName="S1">
        <Address>
          <P type="IP">192.168.10.13</P>
          <P type="IP-SUBNET">255.255.255.0</P>
          <P type="IP-GATEWAY">192.168.10.1</P>
          <P type="OSI-PSEL">00000001</P>
          <P type="OSI-SSEL">0001</P>
          <P type="OSI-TSEL">0001</P>
        </Address>
        <!-- GOOSE: Interlock (IED3 publishes) -->
        <GSE ldInst="BAYCTL" cbName="gcbInterlock">
          <Address>
            <P type="MAC-Address">01-0C-CD-01-00-03</P>
            <P type="APPID">0003</P>
            <P type="VLAN-ID">064</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
          <MinTime unit="s" multiplier="m">4</MinTime>
          <MaxTime unit="s" multiplier="m">1000</MaxTime>
        </GSE>
        <Private type="SecurityGateway-SourceMAC">00-30-A7-01-00-03</Private>
      </ConnectedAP>

      <!-- IED4_MergingUnit on Station Bus (MMS only) -->
      <ConnectedAP iedName="IED4_MergingUnit" apName="S1">
        <Address>
          <P type="IP">192.168.10.14</P>
          <P type="IP-SUBNET">255.255.255.0</P>
          <P type="IP-GATEWAY">192.168.10.1</P>
          <P type="OSI-PSEL">00000001</P>
          <P type="OSI-SSEL">0001</P>
          <P type="OSI-TSEL">0001</P>
        </Address>
        <Private type="SecurityGateway-SourceMAC">00-30-A7-01-00-04</Private>
      </ConnectedAP>

      <!-- IED5_StationCtrl on Station Bus -->
      <ConnectedAP iedName="IED5_StationCtrl" apName="S1">
        <Address>
          <P type="IP">192.168.10.15</P>
          <P type="IP-SUBNET">255.255.255.0</P>
          <P type="IP-GATEWAY">192.168.10.1</P>
          <P type="OSI-PSEL">00000001</P>
          <P type="OSI-SSEL">0001</P>
          <P type="OSI-TSEL">0001</P>
        </Address>
        <Private type="SecurityGateway-SourceMAC">00-30-A7-01-00-05</Private>
      </ConnectedAP>
    </SubNetwork>

    <!-- ======== Process Bus (Sampled Values) ======== -->
    <SubNetwork name="ProcessBus" desc="33 kV Process Bus" type="9-2">
      <ConnectedAP iedName="IED4_MergingUnit" apName="P1">
        <Address>
          <P type="IP">192.168.20.14</P>
          <P type="IP-SUBNET">255.255.255.0</P>
        </Address>
        <!-- SV: Merging Unit sampled values -->
        <SMV ldInst="MU" cbName="smvcbMU">
          <Address>
            <P type="MAC-Address">01-0C-CD-04-00-01</P>
            <P type="APPID">4000</P>
            <P type="VLAN-ID">0C8</P>
            <P type="VLAN-PRIORITY">4</P>
          </Address>
        </SMV>
        <Private type="SecurityGateway-SourceMAC">00-30-A7-01-00-04</Private>
      </ConnectedAP>
    </SubNetwork>
  </Communication>

  <!-- ============================================================ -->
  <!-- IED 1: BREAKER 52A CONTROLLER                                -->
  <!-- ============================================================ -->
  <IED name="IED1_Breaker52A" desc="Circuit Breaker 52A Controller" manufacturer="ABB" type="REF615" configVersion="1.0">
    <Services>
      <DynAssociation/>
      <GetDirectory/>
      <GetDataObjectDefinition/>
      <GetDataSetValue/>
      <DataSetDirectory/>
      <ConfDataSet max="10" maxAttributes="50"/>
      <ReadWrite/>
      <ConfReportControl max="10"/>
      <GetCBValues/>
      <ReportSettings cbName="Fix" datSet="Fix" rptID="Dyn" optFields="Fix" bufTime="Dyn" trgOps="Dyn" intgPd="Dyn"/>
      <GSESettings cbName="Fix" datSet="Fix" appID="Fix"/>
      <GOOSE max="4"/>
      <ConfLNs fixPrefix="true" fixLnInst="true"/>
      <ClientServices goose="true" gsse="false" bufReport="true" unbufReport="true"/>
    </Services>
    <AccessPoint name="S1">
      <Server>
        <Authentication none="true"/>
        <LDevice inst="CTRL" desc="Breaker Control">
          <!-- LLN0 -->
          <LN0 lnClass="LLN0" inst="" lnType="LN_LLN0">
            <!-- DS_BreakerStatus: published via GOOSE and Report -->
            <DataSet name="DS_BreakerStatus" desc="Breaker status dataset">
              <FCDA ldInst="CTRL" prefix="" lnClass="XCBR" lnInst="1" doName="Pos" daName="stVal" fc="ST"/>
              <FCDA ldInst="CTRL" prefix="" lnClass="XCBR" lnInst="1" doName="Pos" daName="q" fc="ST"/>
              <FCDA ldInst="CTRL" prefix="" lnClass="XCBR" lnInst="1" doName="OpCnt" daName="stVal" fc="ST"/>
              <FCDA ldInst="CTRL" prefix="" lnClass="XCBR" lnInst="1" doName="Beh" daName="stVal" fc="ST"/>
              <FCDA ldInst="CTRL" prefix="" lnClass="XCBR" lnInst="1" doName="Health" daName="stVal" fc="ST"/>
              <FCDA ldInst="CTRL" prefix="" lnClass="XCBR" lnInst="1" doName="Loc" daName="stVal" fc="ST"/>
            </DataSet>
            <!-- DS_BreakerTrip: for trip indication reporting -->
            <DataSet name="DS_BreakerTrip" desc="Breaker trip indication dataset">
              <FCDA ldInst="CTRL" prefix="" lnClass="XCBR" lnInst="1" doName="Pos" daName="stVal" fc="ST"/>
              <FCDA ldInst="CTRL" prefix="" lnClass="XCBR" lnInst="1" doName="Pos" daName="q" fc="ST"/>
              <FCDA ldInst="CTRL" prefix="" lnClass="CSWI" lnInst="1" doName="Pos" daName="stVal" fc="ST"/>
            </DataSet>

            <!-- GOOSE: Breaker Status publisher -->
            <GSEControl name="gcbBreakerStatus" desc="GOOSE Breaker Status" datSet="DS_BreakerStatus" confRev="1" type="GOOSE" appID="IED1_Breaker52ACTRL/LLN0.gcbBreakerStatus"/>

            <!-- Buffered Report: Breaker Status -->
            <ReportControl name="brcbBreakerStatus" desc="Buffered Report - Breaker Status" datSet="DS_BreakerStatus" confRev="1" buffered="true" rptID="IED1_CTRL/LLN0$BR$brcbBreakerStatus" intgPd="60000">
              <TrgOps dchg="true" qchg="true" dupd="false" period="true"/>
              <OptFields seqNum="true" timeStamp="true" dataSet="true" reasonCode="true" dataRef="true" entryID="true" configRef="true"/>
              <RptEnabled max="3"/>
            </ReportControl>
            <!-- Unbuffered Report: Breaker Trip -->
            <ReportControl name="urcbBreakerTrip" desc="Unbuffered Report - Breaker Trip" datSet="DS_BreakerTrip" confRev="1" buffered="false" rptID="IED1_CTRL/LLN0$RP$urcbBreakerTrip" intgPd="0">
              <TrgOps dchg="true" qchg="true" dupd="false" period="false"/>
              <OptFields seqNum="true" timeStamp="true" dataSet="true" reasonCode="true" dataRef="false" entryID="false" configRef="true"/>
              <RptEnabled max="2"/>
            </ReportControl>

            <!-- Subscriptions: IED1 subscribes to IED2 Trip Command and IED3 Interlock -->
            <Inputs>
              <!-- Subscribe to IED2 Trip Command -->
              <ExtRef iedName="IED2_Protection" ldInst="PROT" lnClass="PTRC" lnInst="1" doName="Op" daName="general" serviceType="GOOSE" srcLDInst="PROT" srcLNClass="LLN0" srcCBName="gcbTripCommand"/>
              <ExtRef iedName="IED2_Protection" ldInst="PROT" lnClass="PTRC" lnInst="1" doName="Op" daName="q" serviceType="GOOSE" srcLDInst="PROT" srcLNClass="LLN0" srcCBName="gcbTripCommand"/>
              <!-- Subscribe to IED3 Interlock -->
              <ExtRef iedName="IED3_BayControl" ldInst="BAYCTL" lnClass="CILO" lnInst="1" doName="EnaOpn" daName="stVal" serviceType="GOOSE" srcLDInst="BAYCTL" srcLNClass="LLN0" srcCBName="gcbInterlock"/>
              <ExtRef iedName="IED3_BayControl" ldInst="BAYCTL" lnClass="CILO" lnInst="1" doName="EnaCls" daName="stVal" serviceType="GOOSE" srcLDInst="BAYCTL" srcLNClass="LLN0" srcCBName="gcbInterlock"/>
            </Inputs>
          </LN0>
          <LN lnClass="LPHD" inst="1" lnType="LN_LPHD"/>
          <LN lnClass="XCBR" inst="1" lnType="LN_XCBR" desc="Circuit Breaker 52A"/>
          <LN lnClass="CSWI" inst="1" lnType="LN_CSWI" desc="Switch Controller"/>
          <LN lnClass="CILO" inst="1" lnType="LN_CILO" desc="Interlocking"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>

  <!-- ============================================================ -->
  <!-- IED 2: PROTECTION RELAY                                      -->
  <!-- ============================================================ -->
  <IED name="IED2_Protection" desc="Overcurrent Protection Relay" manufacturer="Siemens" type="7SJ85" configVersion="1.0">
    <Services>
      <DynAssociation/>
      <GetDirectory/>
      <GetDataObjectDefinition/>
      <GetDataSetValue/>
      <DataSetDirectory/>
      <ConfDataSet max="10" maxAttributes="50"/>
      <ReadWrite/>
      <ConfReportControl max="10"/>
      <GetCBValues/>
      <ReportSettings cbName="Fix" datSet="Fix" rptID="Dyn" optFields="Fix" bufTime="Dyn" trgOps="Dyn" intgPd="Dyn"/>
      <GSESettings cbName="Fix" datSet="Fix" appID="Fix"/>
      <GOOSE max="4"/>
      <ConfLNs fixPrefix="true" fixLnInst="true"/>
      <ClientServices goose="true" gsse="false" bufReport="true" unbufReport="true"/>
    </Services>
    <AccessPoint name="S1">
      <Server>
        <Authentication none="true"/>
        <LDevice inst="PROT" desc="Protection Functions">
          <LN0 lnClass="LLN0" inst="" lnType="LN_LLN0">
            <!-- DS_ProtectionStatus -->
            <DataSet name="DS_ProtectionStatus" desc="Protection status dataset">
              <FCDA ldInst="PROT" prefix="" lnClass="PTOC" lnInst="1" doName="Str" daName="general" fc="ST"/>
              <FCDA ldInst="PROT" prefix="" lnClass="PTOC" lnInst="1" doName="Op" daName="general" fc="ST"/>
              <FCDA ldInst="PROT" prefix="" lnClass="PTOC" lnInst="1" doName="Op" daName="q" fc="ST"/>
              <FCDA ldInst="PROT" prefix="" lnClass="PTRC" lnInst="1" doName="Op" daName="general" fc="ST"/>
              <FCDA ldInst="PROT" prefix="" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" fc="ST"/>
            </DataSet>
            <!-- DS_TripCommand -->
            <DataSet name="DS_TripCommand" desc="Trip command dataset">
              <FCDA ldInst="PROT" prefix="" lnClass="PTRC" lnInst="1" doName="Op" daName="general" fc="ST"/>
              <FCDA ldInst="PROT" prefix="" lnClass="PTRC" lnInst="1" doName="Op" daName="q" fc="ST"/>
              <FCDA ldInst="PROT" prefix="" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" fc="ST"/>
              <FCDA ldInst="PROT" prefix="" lnClass="PTRC" lnInst="1" doName="Tr" daName="q" fc="ST"/>
            </DataSet>

            <!-- GOOSE: Trip Command publisher -->
            <GSEControl name="gcbTripCommand" desc="GOOSE Trip Command" datSet="DS_TripCommand" confRev="1" type="GOOSE" appID="IED2_ProtectionPROT/LLN0.gcbTripCommand"/>
            <!-- GOOSE: Protection Status publisher -->
            <GSEControl name="gcbProtStatus" desc="GOOSE Protection Status" datSet="DS_ProtectionStatus" confRev="1" type="GOOSE" appID="IED2_ProtectionPROT/LLN0.gcbProtStatus"/>

            <!-- Buffered Report: Protection Status -->
            <ReportControl name="brcbProtStatus" desc="Buffered Report - Protection Status" datSet="DS_ProtectionStatus" confRev="1" buffered="true" rptID="IED2_PROT/LLN0$BR$brcbProtStatus" intgPd="60000">
              <TrgOps dchg="true" qchg="true" dupd="false" period="true"/>
              <OptFields seqNum="true" timeStamp="true" dataSet="true" reasonCode="true" dataRef="true" entryID="true" configRef="true"/>
              <RptEnabled max="3"/>
            </ReportControl>
            <!-- Unbuffered Report: Trip Command -->
            <ReportControl name="urcbTripCommand" desc="Unbuffered Report - Trip Command" datSet="DS_TripCommand" confRev="1" buffered="false" rptID="IED2_PROT/LLN0$RP$urcbTripCommand" intgPd="0">
              <TrgOps dchg="true" qchg="true" dupd="false" period="false"/>
              <OptFields seqNum="true" timeStamp="true" dataSet="true" reasonCode="true" dataRef="false" entryID="false" configRef="true"/>
              <RptEnabled max="2"/>
            </ReportControl>

            <!-- Subscriptions: IED2 subscribes to IED1 Breaker Status -->
            <Inputs>
              <ExtRef iedName="IED1_Breaker52A" ldInst="CTRL" lnClass="XCBR" lnInst="1" doName="Pos" daName="stVal" serviceType="GOOSE" srcLDInst="CTRL" srcLNClass="LLN0" srcCBName="gcbBreakerStatus"/>
              <ExtRef iedName="IED1_Breaker52A" ldInst="CTRL" lnClass="XCBR" lnInst="1" doName="Pos" daName="q" serviceType="GOOSE" srcLDInst="CTRL" srcLNClass="LLN0" srcCBName="gcbBreakerStatus"/>
              <ExtRef iedName="IED1_Breaker52A" ldInst="CTRL" lnClass="XCBR" lnInst="1" doName="Beh" daName="stVal" serviceType="GOOSE" srcLDInst="CTRL" srcLNClass="LLN0" srcCBName="gcbBreakerStatus"/>
            </Inputs>
          </LN0>
          <LN lnClass="LPHD" inst="1" lnType="LN_LPHD"/>
          <LN lnClass="PTOC" inst="1" lnType="LN_PTOC" desc="Time Overcurrent Protection"/>
          <LN lnClass="PTRC" inst="1" lnType="LN_PTRC" desc="Protection Trip Conditioning"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>

  <!-- ============================================================ -->
  <!-- IED 3: BAY CONTROLLER                                        -->
  <!-- ============================================================ -->
  <IED name="IED3_BayControl" desc="Bay Controller Unit" manufacturer="GE" type="D60" configVersion="1.0">
    <Services>
      <DynAssociation/>
      <GetDirectory/>
      <GetDataObjectDefinition/>
      <GetDataSetValue/>
      <DataSetDirectory/>
      <ConfDataSet max="10" maxAttributes="50"/>
      <ReadWrite/>
      <ConfReportControl max="10"/>
      <GetCBValues/>
      <ReportSettings cbName="Fix" datSet="Fix" rptID="Dyn" optFields="Fix" bufTime="Dyn" trgOps="Dyn" intgPd="Dyn"/>
      <GSESettings cbName="Fix" datSet="Fix" appID="Fix"/>
      <GOOSE max="4"/>
      <ConfLNs fixPrefix="true" fixLnInst="true"/>
      <ClientServices goose="true" gsse="false" bufReport="true" unbufReport="true"/>
    </Services>
    <AccessPoint name="S1">
      <Server>
        <Authentication none="true"/>
        <LDevice inst="BAYCTL" desc="Bay Control Functions">
          <LN0 lnClass="LLN0" inst="" lnType="LN_LLN0">
            <!-- DS_Interlock -->
            <DataSet name="DS_Interlock" desc="Interlocking status dataset">
              <FCDA ldInst="BAYCTL" prefix="" lnClass="CILO" lnInst="1" doName="EnaOpn" daName="stVal" fc="ST"/>
              <FCDA ldInst="BAYCTL" prefix="" lnClass="CILO" lnInst="1" doName="EnaOpn" daName="q" fc="ST"/>
              <FCDA ldInst="BAYCTL" prefix="" lnClass="CILO" lnInst="1" doName="EnaCls" daName="stVal" fc="ST"/>
              <FCDA ldInst="BAYCTL" prefix="" lnClass="CILO" lnInst="1" doName="EnaCls" daName="q" fc="ST"/>
            </DataSet>
            <!-- DS_BayStatus -->
            <DataSet name="DS_BayStatus" desc="Bay status dataset">
              <FCDA ldInst="BAYCTL" prefix="" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
              <FCDA ldInst="BAYCTL" prefix="" lnClass="GGIO" lnInst="1" doName="Ind2" daName="stVal" fc="ST"/>
              <FCDA ldInst="BAYCTL" prefix="" lnClass="LLN0" lnInst="" doName="Beh" daName="stVal" fc="ST"/>
              <FCDA ldInst="BAYCTL" prefix="" lnClass="LLN0" lnInst="" doName="Health" daName="stVal" fc="ST"/>
            </DataSet>

            <!-- GOOSE: Interlock publisher -->
            <GSEControl name="gcbInterlock" desc="GOOSE Interlock Status" datSet="DS_Interlock" confRev="1" type="GOOSE" appID="IED3_BayControlBAYCTL/LLN0.gcbInterlock"/>

            <!-- Buffered Report: Bay Status -->
            <ReportControl name="brcbBayStatus" desc="Buffered Report - Bay Status" datSet="DS_BayStatus" confRev="1" buffered="true" rptID="IED3_BAYCTL/LLN0$BR$brcbBayStatus" intgPd="60000">
              <TrgOps dchg="true" qchg="true" dupd="false" period="true"/>
              <OptFields seqNum="true" timeStamp="true" dataSet="true" reasonCode="true" dataRef="true" entryID="true" configRef="true"/>
              <RptEnabled max="3"/>
            </ReportControl>
            <!-- Buffered Report: Interlock -->
            <ReportControl name="brcbInterlock" desc="Buffered Report - Interlock" datSet="DS_Interlock" confRev="1" buffered="true" rptID="IED3_BAYCTL/LLN0$BR$brcbInterlock" intgPd="60000">
              <TrgOps dchg="true" qchg="true" dupd="false" period="true"/>
              <OptFields seqNum="true" timeStamp="true" dataSet="true" reasonCode="true" dataRef="true" entryID="true" configRef="true"/>
              <RptEnabled max="3"/>
            </ReportControl>

            <!-- Subscriptions: IED3 subscribes to IED2 Protection Status -->
            <Inputs>
              <ExtRef iedName="IED2_Protection" ldInst="PROT" lnClass="PTOC" lnInst="1" doName="Str" daName="general" serviceType="GOOSE" srcLDInst="PROT" srcLNClass="LLN0" srcCBName="gcbProtStatus"/>
              <ExtRef iedName="IED2_Protection" ldInst="PROT" lnClass="PTOC" lnInst="1" doName="Op" daName="general" serviceType="GOOSE" srcLDInst="PROT" srcLNClass="LLN0" srcCBName="gcbProtStatus"/>
              <ExtRef iedName="IED2_Protection" ldInst="PROT" lnClass="PTRC" lnInst="1" doName="Tr" daName="general" serviceType="GOOSE" srcLDInst="PROT" srcLNClass="LLN0" srcCBName="gcbProtStatus"/>
            </Inputs>
          </LN0>
          <LN lnClass="LPHD" inst="1" lnType="LN_LPHD"/>
          <LN lnClass="CSWI" inst="1" lnType="LN_CSWI" desc="Bay Switch Controller"/>
          <LN lnClass="CILO" inst="1" lnType="LN_CILO" desc="Bay Interlocking"/>
          <LN lnClass="GGIO" inst="1" lnType="LN_GGIO" desc="Bay Generic I/O"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>

  <!-- ============================================================ -->
  <!-- IED 4: MERGING UNIT                                          -->
  <!-- ============================================================ -->
  <IED name="IED4_MergingUnit" desc="3-Phase Merging Unit" manufacturer="Schneider" type="MU320" configVersion="1.0">
    <Services>
      <DynAssociation/>
      <GetDirectory/>
      <GetDataObjectDefinition/>
      <GetDataSetValue/>
      <DataSetDirectory/>
      <ConfDataSet max="10" maxAttributes="100"/>
      <ReadWrite/>
      <ConfReportControl max="5"/>
      <GetCBValues/>
      <ReportSettings cbName="Fix" datSet="Fix" rptID="Dyn" optFields="Fix" bufTime="Dyn" trgOps="Dyn" intgPd="Dyn"/>
      <SMVSettings cbName="Fix" datSet="Fix" svID="Fix" optFields="Fix" smpRate="Fix"/>
      <SMVsc max="1"/>
      <ConfLNs fixPrefix="true" fixLnInst="true"/>
    </Services>
    <AccessPoint name="S1">
      <Server>
        <Authentication none="true"/>
        <LDevice inst="MU" desc="Merging Unit">
          <LN0 lnClass="LLN0" inst="" lnType="LN_LLN0">
            <!-- DS_SampledValues: 3-phase current + 3-phase voltage -->
            <DataSet name="DS_SampledValues" desc="Sampled values dataset (3ph I + 3ph V)">
              <FCDA ldInst="MU" prefix="" lnClass="TCTR" lnInst="1" doName="AmpSv" fc="MX"/>
              <FCDA ldInst="MU" prefix="" lnClass="TCTR" lnInst="2" doName="AmpSv" fc="MX"/>
              <FCDA ldInst="MU" prefix="" lnClass="TCTR" lnInst="3" doName="AmpSv" fc="MX"/>
              <FCDA ldInst="MU" prefix="" lnClass="TVTR" lnInst="1" doName="VolSv" fc="MX"/>
              <FCDA ldInst="MU" prefix="" lnClass="TVTR" lnInst="2" doName="VolSv" fc="MX"/>
              <FCDA ldInst="MU" prefix="" lnClass="TVTR" lnInst="3" doName="VolSv" fc="MX"/>
            </DataSet>
            <!-- DS_Measurements: RMS measurements for MMS reporting -->
            <DataSet name="DS_Measurements" desc="Measurement dataset (MMXU RMS values)">
              <FCDA ldInst="MU" prefix="" lnClass="MMXU" lnInst="1" doName="TotW" fc="MX"/>
              <FCDA ldInst="MU" prefix="" lnClass="MMXU" lnInst="1" doName="TotVAr" fc="MX"/>
              <FCDA ldInst="MU" prefix="" lnClass="MMXU" lnInst="1" doName="Hz" fc="MX"/>
              <FCDA ldInst="MU" prefix="" lnClass="MMXU" lnInst="1" doName="A" fc="MX"/>
              <FCDA ldInst="MU" prefix="" lnClass="MMXU" lnInst="1" doName="PhV" fc="MX"/>
              <FCDA ldInst="MU" prefix="" lnClass="MMXU" lnInst="1" doName="PPV" fc="MX"/>
            </DataSet>

            <!-- SV Control: Merging Unit publishes sampled values -->
            <SampledValueControl name="smvcbMU" desc="SV Stream - 3ph Current and Voltage" datSet="DS_SampledValues" smvID="IED4_MergingUnitMU/LLN0.smvcbMU" confRev="1" smpRate="4000" nofASDU="1" multicast="true">
              <SmvOpts sampleRate="true" dataSet="true" timestamp="true" security="false" synchSourceId="false"/>
            </SampledValueControl>

            <!-- Buffered Report: Measurements -->
            <ReportControl name="brcbMeasurements" desc="Buffered Report - Measurements" datSet="DS_Measurements" confRev="1" buffered="true" rptID="IED4_MU/LLN0$BR$brcbMeasurements" intgPd="10000">
              <TrgOps dchg="true" qchg="true" dupd="true" period="true"/>
              <OptFields seqNum="true" timeStamp="true" dataSet="true" reasonCode="true" dataRef="true" entryID="true" configRef="true"/>
              <RptEnabled max="3"/>
            </ReportControl>
          </LN0>
          <LN lnClass="LPHD" inst="1" lnType="LN_LPHD"/>
          <LN lnClass="TCTR" inst="1" lnType="LN_TCTR" desc="Phase A Current Transformer"/>
          <LN lnClass="TCTR" inst="2" lnType="LN_TCTR" desc="Phase B Current Transformer"/>
          <LN lnClass="TCTR" inst="3" lnType="LN_TCTR" desc="Phase C Current Transformer"/>
          <LN lnClass="TVTR" inst="1" lnType="LN_TVTR" desc="Phase A Voltage Transformer"/>
          <LN lnClass="TVTR" inst="2" lnType="LN_TVTR" desc="Phase B Voltage Transformer"/>
          <LN lnClass="TVTR" inst="3" lnType="LN_TVTR" desc="Phase C Voltage Transformer"/>
          <LN lnClass="MMXU" inst="1" lnType="LN_MMXU" desc="Measurement Unit"/>
        </LDevice>
      </Server>
    </AccessPoint>
    <!-- Process Bus access point (SV traffic only, no MMS server) -->
    <AccessPoint name="P1" desc="Process Bus Interface"/>
  </IED>

  <!-- ============================================================ -->
  <!-- IED 5: STATION CONTROLLER                                    -->
  <!-- ============================================================ -->
  <IED name="IED5_StationCtrl" desc="Station Controller / Gateway" manufacturer="SEL" type="SEL-3530" configVersion="1.0">
    <Services>
      <DynAssociation/>
      <GetDirectory/>
      <GetDataObjectDefinition/>
      <GetDataSetValue/>
      <DataSetDirectory/>
      <ConfDataSet max="10" maxAttributes="50"/>
      <ReadWrite/>
      <ConfReportControl max="10"/>
      <GetCBValues/>
      <ReportSettings cbName="Fix" datSet="Fix" rptID="Dyn" optFields="Fix" bufTime="Dyn" trgOps="Dyn" intgPd="Dyn"/>
      <ConfLNs fixPrefix="true" fixLnInst="true"/>
      <ClientServices goose="true" gsse="false" bufReport="true" unbufReport="true" readLog="true"/>
    </Services>
    <AccessPoint name="S1">
      <Server>
        <Authentication none="true"/>
        <LDevice inst="STCTL" desc="Station Control">
          <LN0 lnClass="LLN0" inst="" lnType="LN_LLN0">
            <!-- DS_StationStatus -->
            <DataSet name="DS_StationStatus" desc="Station status dataset">
              <FCDA ldInst="STCTL" prefix="" lnClass="GGIO" lnInst="1" doName="Ind1" daName="stVal" fc="ST"/>
              <FCDA ldInst="STCTL" prefix="" lnClass="GGIO" lnInst="1" doName="Ind2" daName="stVal" fc="ST"/>
              <FCDA ldInst="STCTL" prefix="" lnClass="LLN0" lnInst="" doName="Beh" daName="stVal" fc="ST"/>
              <FCDA ldInst="STCTL" prefix="" lnClass="LLN0" lnInst="" doName="Health" daName="stVal" fc="ST"/>
            </DataSet>

            <!-- Buffered Report: Station Status -->
            <ReportControl name="brcbStationStatus" desc="Buffered Report - Station Status" datSet="DS_StationStatus" confRev="1" buffered="true" rptID="IED5_STCTL/LLN0$BR$brcbStationStatus" intgPd="60000">
              <TrgOps dchg="true" qchg="true" dupd="false" period="true"/>
              <OptFields seqNum="true" timeStamp="true" dataSet="true" reasonCode="true" dataRef="true" entryID="true" configRef="true"/>
              <RptEnabled max="5"/>
            </ReportControl>
          </LN0>
          <LN lnClass="LPHD" inst="1" lnType="LN_LPHD"/>
          <LN lnClass="GGIO" inst="1" lnType="LN_GGIO" desc="Station Generic I/O"/>
        </LDevice>
      </Server>
    </AccessPoint>
  </IED>

  <!-- ============================================================ -->
  <!-- DATA TYPE TEMPLATES                                          -->
  <!-- ============================================================ -->
  <DataTypeTemplates>

    <!-- ======== Logical Node Types ======== -->

    <!-- LLN0: Logical Node Zero (common for all IEDs) -->
    <LNodeType id="LN_LLN0" lnClass="LLN0" desc="Logical Node Zero">
      <DO name="Mod" type="DO_ENC" desc="Mode"/>
      <DO name="Beh" type="DO_ENS_BehKind" desc="Behaviour"/>
      <DO name="Health" type="DO_ENS_HealthKind" desc="Health"/>
      <DO name="NamPlt" type="DO_LPL" desc="Name Plate"/>
    </LNodeType>

    <!-- LPHD: Physical Device -->
    <LNodeType id="LN_LPHD" lnClass="LPHD" desc="Physical Device Information">
      <DO name="PhyHealth" type="DO_ENS_HealthKind" desc="Physical Health"/>
      <DO name="PhyNam" type="DO_DPL" desc="Physical Name Plate"/>
      <DO name="Proxy" type="DO_SPS" desc="Proxy Indicator"/>
    </LNodeType>

    <!-- XCBR: Circuit Breaker -->
    <LNodeType id="LN_XCBR" lnClass="XCBR" desc="Circuit Breaker">
      <DO name="Mod" type="DO_ENC" desc="Mode"/>
      <DO name="Beh" type="DO_ENS_BehKind" desc="Behaviour"/>
      <DO name="Health" type="DO_ENS_HealthKind" desc="Health"/>
      <DO name="NamPlt" type="DO_LPL" desc="Name Plate"/>
      <DO name="Loc" type="DO_SPS" desc="Local Operation"/>
      <DO name="OpCnt" type="DO_INS" desc="Operation Counter"/>
      <DO name="Pos" type="DO_DPC" desc="Position"/>
      <DO name="BlkOpn" type="DO_SPC" desc="Block Opening"/>
      <DO name="BlkCls" type="DO_SPC" desc="Block Closing"/>
    </LNodeType>

    <!-- CSWI: Switch Controller -->
    <LNodeType id="LN_CSWI" lnClass="CSWI" desc="Switch Controller">
      <DO name="Mod" type="DO_ENC" desc="Mode"/>
      <DO name="Beh" type="DO_ENS_BehKind" desc="Behaviour"/>
      <DO name="Health" type="DO_ENS_HealthKind" desc="Health"/>
      <DO name="NamPlt" type="DO_LPL" desc="Name Plate"/>
      <DO name="Loc" type="DO_SPS" desc="Local Operation"/>
      <DO name="Pos" type="DO_DPC" desc="Position"/>
    </LNodeType>

    <!-- CILO: Interlocking -->
    <LNodeType id="LN_CILO" lnClass="CILO" desc="Interlocking">
      <DO name="Mod" type="DO_ENC" desc="Mode"/>
      <DO name="Beh" type="DO_ENS_BehKind" desc="Behaviour"/>
      <DO name="Health" type="DO_ENS_HealthKind" desc="Health"/>
      <DO name="NamPlt" type="DO_LPL" desc="Name Plate"/>
      <DO name="EnaOpn" type="DO_SPS" desc="Enable Open"/>
      <DO name="EnaCls" type="DO_SPS" desc="Enable Close"/>
    </LNodeType>

    <!-- PTOC: Time Overcurrent Protection -->
    <LNodeType id="LN_PTOC" lnClass="PTOC" desc="Time Overcurrent Protection">
      <DO name="Mod" type="DO_ENC" desc="Mode"/>
      <DO name="Beh" type="DO_ENS_BehKind" desc="Behaviour"/>
      <DO name="Health" type="DO_ENS_HealthKind" desc="Health"/>
      <DO name="NamPlt" type="DO_LPL" desc="Name Plate"/>
      <DO name="Str" type="DO_ACD" desc="Start"/>
      <DO name="Op" type="DO_ACT" desc="Operate"/>
    </LNodeType>

    <!-- PTRC: Protection Trip Conditioning -->
    <LNodeType id="LN_PTRC" lnClass="PTRC" desc="Protection Trip Conditioning">
      <DO name="Mod" type="DO_ENC" desc="Mode"/>
      <DO name="Beh" type="DO_ENS_BehKind" desc="Behaviour"/>
      <DO name="Health" type="DO_ENS_HealthKind" desc="Health"/>
      <DO name="NamPlt" type="DO_LPL" desc="Name Plate"/>
      <DO name="Tr" type="DO_ACT" desc="Trip"/>
      <DO name="Op" type="DO_ACT" desc="Operate"/>
    </LNodeType>

    <!-- TCTR: Current Transformer -->
    <LNodeType id="LN_TCTR" lnClass="TCTR" desc="Current Transformer">
      <DO name="Mod" type="DO_ENC" desc="Mode"/>
      <DO name="Beh" type="DO_ENS_BehKind" desc="Behaviour"/>
      <DO name="Health" type="DO_ENS_HealthKind" desc="Health"/>
      <DO name="NamPlt" type="DO_LPL" desc="Name Plate"/>
      <DO name="AmpSv" type="DO_SAV" desc="Sampled Current Value"/>
      <DO name="Amp" type="DO_MV" desc="RMS Current"/>
    </LNodeType>

    <!-- TVTR: Voltage Transformer -->
    <LNodeType id="LN_TVTR" lnClass="TVTR" desc="Voltage Transformer">
      <DO name="Mod" type="DO_ENC" desc="Mode"/>
      <DO name="Beh" type="DO_ENS_BehKind" desc="Behaviour"/>
      <DO name="Health" type="DO_ENS_HealthKind" desc="Health"/>
      <DO name="NamPlt" type="DO_LPL" desc="Name Plate"/>
      <DO name="VolSv" type="DO_SAV" desc="Sampled Voltage Value"/>
      <DO name="Vol" type="DO_MV" desc="RMS Voltage"/>
    </LNodeType>

    <!-- MMXU: Measurement Unit -->
    <LNodeType id="LN_MMXU" lnClass="MMXU" desc="Measurement Unit">
      <DO name="Mod" type="DO_ENC" desc="Mode"/>
      <DO name="Beh" type="DO_ENS_BehKind" desc="Behaviour"/>
      <DO name="Health" type="DO_ENS_HealthKind" desc="Health"/>
      <DO name="NamPlt" type="DO_LPL" desc="Name Plate"/>
      <DO name="TotW" type="DO_MV" desc="Total Active Power"/>
      <DO name="TotVAr" type="DO_MV" desc="Total Reactive Power"/>
      <DO name="Hz" type="DO_MV" desc="Frequency"/>
      <DO name="A" type="DO_WYE" desc="Phase Currents"/>
      <DO name="PhV" type="DO_WYE" desc="Phase Voltages"/>
      <DO name="PPV" type="DO_DEL" desc="Phase-to-Phase Voltages"/>
    </LNodeType>

    <!-- GGIO: Generic Generic I/O -->
    <LNodeType id="LN_GGIO" lnClass="GGIO" desc="Generic Process I/O">
      <DO name="Mod" type="DO_ENC" desc="Mode"/>
      <DO name="Beh" type="DO_ENS_BehKind" desc="Behaviour"/>
      <DO name="Health" type="DO_ENS_HealthKind" desc="Health"/>
      <DO name="NamPlt" type="DO_LPL" desc="Name Plate"/>
      <DO name="Ind1" type="DO_SPS" desc="Indication 1"/>
      <DO name="Ind2" type="DO_SPS" desc="Indication 2"/>
      <DO name="SPCSO1" type="DO_SPC" desc="Single Point Control 1"/>
    </LNodeType>

    <!-- ======== Data Object Types (CDCs) ======== -->

    <!-- SPS: Single Point Status -->
    <DOType id="DO_SPS" cdc="SPS" desc="Single Point Status">
      <DA name="stVal" bType="BOOLEAN" fc="ST" dchg="true"/>
      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="ST"/>
    </DOType>

    <!-- DPS: Double Point Status -->
    <DOType id="DO_DPS" cdc="DPS" desc="Double Point Status">
      <DA name="stVal" bType="Enum" type="Dbpos" fc="ST" dchg="true"/>
      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="ST"/>
    </DOType>

    <!-- INS: Integer Status -->
    <DOType id="DO_INS" cdc="INS" desc="Integer Status">
      <DA name="stVal" bType="INT32" fc="ST" dchg="true"/>
      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="ST"/>
    </DOType>

    <!-- ENS: Enumerated Status (Behaviour) -->
    <DOType id="DO_ENS_BehKind" cdc="ENS" desc="Enumerated Status - Behaviour">
      <DA name="stVal" bType="Enum" type="BehaviourModeKind" fc="ST" dchg="true"/>
      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="ST"/>
    </DOType>

    <!-- ENS: Enumerated Status (Health) -->
    <DOType id="DO_ENS_HealthKind" cdc="ENS" desc="Enumerated Status - Health">
      <DA name="stVal" bType="Enum" type="HealthKind" fc="ST" dchg="true"/>
      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="ST"/>
    </DOType>

    <!-- ENC: Enumerated Controllable (for Mod) - Edition 2.1 -->
    <DOType id="DO_ENC" cdc="ENC" desc="Enumerated Controllable Status">
      <DA name="stVal" bType="Enum" type="BehaviourModeKind" fc="ST" dchg="true"/>
      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="ST"/>
      <DA name="ctlModel" bType="Enum" type="CtlModelKind" fc="CF"/>
    </DOType>

    <!-- DPC: Double Point Controllable -->
    <DOType id="DO_DPC" cdc="DPC" desc="Double Point Controllable">
      <DA name="stVal" bType="Enum" type="Dbpos" fc="ST" dchg="true"/>
      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="ST"/>
      <DA name="ctlModel" bType="Enum" type="CtlModelKind" fc="CF"/>
      <DA name="Oper" bType="Struct" type="DA_Oper_DPC" fc="CO"/>
    </DOType>

    <!-- SPC: Single Point Controllable -->
    <DOType id="DO_SPC" cdc="SPC" desc="Single Point Controllable">
      <DA name="stVal" bType="BOOLEAN" fc="ST" dchg="true"/>
      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="ST"/>
      <DA name="ctlModel" bType="Enum" type="CtlModelKind" fc="CF"/>
      <DA name="Oper" bType="Struct" type="DA_Oper_SPC" fc="CO"/>
    </DOType>

    <!-- MV: Measured Value -->
    <DOType id="DO_MV" cdc="MV" desc="Measured Value">
      <DA name="mag" bType="Struct" type="DA_AnalogueValue" fc="MX" dchg="true"/>
      <DA name="q" bType="Quality" fc="MX" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="MX"/>
      <DA name="units" bType="Struct" type="DA_Unit" fc="CF"/>
    </DOType>

    <!-- CMV: Complex Measured Value -->
    <DOType id="DO_CMV" cdc="CMV" desc="Complex Measured Value">
      <DA name="cVal" bType="Struct" type="DA_Vector" fc="MX" dchg="true"/>
      <DA name="q" bType="Quality" fc="MX" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="MX"/>
      <DA name="units" bType="Struct" type="DA_Unit" fc="CF"/>
    </DOType>

    <!-- WYE: Phase-to-ground measurement (3-phase) -->
    <DOType id="DO_WYE" cdc="WYE" desc="Three-Phase Measurement (Wye)">
      <SDO name="phsA" type="DO_CMV" desc="Phase A"/>
      <SDO name="phsB" type="DO_CMV" desc="Phase B"/>
      <SDO name="phsC" type="DO_CMV" desc="Phase C"/>
    </DOType>

    <!-- DEL: Phase-to-phase measurement (Delta) -->
    <DOType id="DO_DEL" cdc="DEL" desc="Three-Phase Measurement (Delta)">
      <SDO name="phsAB" type="DO_CMV" desc="Phase A-B"/>
      <SDO name="phsBC" type="DO_CMV" desc="Phase B-C"/>
      <SDO name="phsCA" type="DO_CMV" desc="Phase C-A"/>
    </DOType>

    <!-- ACD: Directional Protection Activation -->
    <DOType id="DO_ACD" cdc="ACD" desc="Directional Protection Activation">
      <DA name="general" bType="BOOLEAN" fc="ST" dchg="true"/>
      <DA name="dirGeneral" bType="Enum" type="ACDdir" fc="ST" dchg="true"/>
      <DA name="phsA" bType="BOOLEAN" fc="ST" dchg="true"/>
      <DA name="dirPhsA" bType="Enum" type="ACDdir" fc="ST" dchg="true"/>
      <DA name="phsB" bType="BOOLEAN" fc="ST" dchg="true"/>
      <DA name="dirPhsB" bType="Enum" type="ACDdir" fc="ST" dchg="true"/>
      <DA name="phsC" bType="BOOLEAN" fc="ST" dchg="true"/>
      <DA name="dirPhsC" bType="Enum" type="ACDdir" fc="ST" dchg="true"/>
      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="ST"/>
    </DOType>

    <!-- ACT: Protection Activation -->
    <DOType id="DO_ACT" cdc="ACT" desc="Protection Activation">
      <DA name="general" bType="BOOLEAN" fc="ST" dchg="true"/>
      <DA name="phsA" bType="BOOLEAN" fc="ST" dchg="true"/>
      <DA name="phsB" bType="BOOLEAN" fc="ST" dchg="true"/>
      <DA name="phsC" bType="BOOLEAN" fc="ST" dchg="true"/>
      <DA name="q" bType="Quality" fc="ST" qchg="true"/>
      <DA name="t" bType="Timestamp" fc="ST"/>
    </DOType>

    <!-- SAV: Sampled Analogue Value -->
    <DOType id="DO_SAV" cdc="SAV" desc="Sampled Analogue Value">
      <DA name="instMag" bType="Struct" type="DA_AnalogueValue" fc="MX"/>
      <DA name="q" bType="Quality" fc="MX"/>
      <DA name="units" bType="Struct" type="DA_Unit" fc="CF"/>
    </DOType>

    <!-- LPL: Logical Node Name Plate -->
    <DOType id="DO_LPL" cdc="LPL" desc="Logical Node Name Plate">
      <DA name="vendor" bType="VisString255" fc="DC"/>
      <DA name="swRev" bType="VisString255" fc="DC"/>
      <DA name="d" bType="VisString255" fc="DC"/>
      <DA name="configRev" bType="VisString255" fc="DC"/>
    </DOType>

    <!-- DPL: Device Name Plate -->
    <DOType id="DO_DPL" cdc="DPL" desc="Device Name Plate">
      <DA name="vendor" bType="VisString255" fc="DC"/>
      <DA name="hwRev" bType="VisString255" fc="DC"/>
      <DA name="swRev" bType="VisString255" fc="DC"/>
      <DA name="serNum" bType="VisString255" fc="DC"/>
      <DA name="model" bType="VisString255" fc="DC"/>
    </DOType>

    <!-- ======== Data Attribute Types ======== -->

    <!-- AnalogueValue -->
    <DAType id="DA_AnalogueValue" desc="Analogue Value">
      <BDA name="f" bType="FLOAT32"/>
    </DAType>

    <!-- Vector (for CMV.cVal) -->
    <DAType id="DA_Vector" desc="Vector Value">
      <BDA name="mag" bType="Struct" type="DA_AnalogueValue"/>
      <BDA name="ang" bType="Struct" type="DA_AnalogueValue"/>
    </DAType>

    <!-- Unit -->
    <DAType id="DA_Unit" desc="Unit">
      <BDA name="SIUnit" bType="Enum" type="SIUnitKind"/>
      <BDA name="multiplier" bType="Enum" type="MultiplierKind"/>
    </DAType>

    <!-- Oper for DPC -->
    <DAType id="DA_Oper_DPC" desc="Operate Structure for DPC">
      <BDA name="ctlVal" bType="Enum" type="Dbpos"/>
      <BDA name="origin" bType="Struct" type="DA_Originator"/>
      <BDA name="ctlNum" bType="INT8U"/>
      <BDA name="T" bType="Timestamp"/>
      <BDA name="Test" bType="BOOLEAN"/>
      <BDA name="Check" bType="Check"/>
    </DAType>

    <!-- Oper for SPC -->
    <DAType id="DA_Oper_SPC" desc="Operate Structure for SPC">
      <BDA name="ctlVal" bType="BOOLEAN"/>
      <BDA name="origin" bType="Struct" type="DA_Originator"/>
      <BDA name="ctlNum" bType="INT8U"/>
      <BDA name="T" bType="Timestamp"/>
      <BDA name="Test" bType="BOOLEAN"/>
      <BDA name="Check" bType="Check"/>
    </DAType>

    <!-- Originator -->
    <DAType id="DA_Originator" desc="Originator">
      <BDA name="orCat" bType="Enum" type="OrCatKind"/>
      <BDA name="orIdent" bType="Octet64"/>
    </DAType>

    <!-- ======== Enumeration Types ======== -->

    <EnumType id="BehaviourModeKind" desc="Behaviour Mode">
      <EnumVal ord="1">on</EnumVal>
      <EnumVal ord="2">blocked</EnumVal>
      <EnumVal ord="3">test</EnumVal>
      <EnumVal ord="4">test/blocked</EnumVal>
      <EnumVal ord="5">off</EnumVal>
    </EnumType>

    <EnumType id="HealthKind" desc="Health">
      <EnumVal ord="1">Ok</EnumVal>
      <EnumVal ord="2">Warning</EnumVal>
      <EnumVal ord="3">Alarm</EnumVal>
    </EnumType>

    <EnumType id="Dbpos" desc="Double Point Position">
      <EnumVal ord="0">intermediate-state</EnumVal>
      <EnumVal ord="1">off</EnumVal>
      <EnumVal ord="2">on</EnumVal>
      <EnumVal ord="3">bad-state</EnumVal>
    </EnumType>

    <EnumType id="CtlModelKind" desc="Control Model">
      <EnumVal ord="0">status-only</EnumVal>
      <EnumVal ord="1">direct-with-normal-security</EnumVal>
      <EnumVal ord="2">sbo-with-normal-security</EnumVal>
      <EnumVal ord="3">direct-with-enhanced-security</EnumVal>
      <EnumVal ord="4">sbo-with-enhanced-security</EnumVal>
    </EnumType>

    <EnumType id="OrCatKind" desc="Originator Category">
      <EnumVal ord="0">not-supported</EnumVal>
      <EnumVal ord="1">bay-control</EnumVal>
      <EnumVal ord="2">station-control</EnumVal>
      <EnumVal ord="3">remote-control</EnumVal>
      <EnumVal ord="4">maintenance</EnumVal>
      <EnumVal ord="5">process</EnumVal>
    </EnumType>

    <EnumType id="ACDdir" desc="Directional Protection Direction">
      <EnumVal ord="0">unknown</EnumVal>
      <EnumVal ord="1">forward</EnumVal>
      <EnumVal ord="2">backward</EnumVal>
      <EnumVal ord="3">both</EnumVal>
    </EnumType>

    <EnumType id="SIUnitKind" desc="SI Unit">
      <EnumVal ord="1"></EnumVal>
      <EnumVal ord="5">A</EnumVal>
      <EnumVal ord="23">Hz</EnumVal>
      <EnumVal ord="27">V</EnumVal>
      <EnumVal ord="28">ohm</EnumVal>
      <EnumVal ord="29">W</EnumVal>
      <EnumVal ord="31">VA</EnumVal>
      <EnumVal ord="32">VAr</EnumVal>
    </EnumType>

    <EnumType id="MultiplierKind" desc="SI Multiplier">
      <EnumVal ord="-6">u</EnumVal>
      <EnumVal ord="-3">m</EnumVal>
      <EnumVal ord="0"></EnumVal>
      <EnumVal ord="3">k</EnumVal>
      <EnumVal ord="6">M</EnumVal>
    </EnumType>

  </DataTypeTemplates>

</SCL>
