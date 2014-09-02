/**
 *  This class interfaces the IRMA card with ABC4Trust
 *  and performs different actions such as randomizing
 *  a CL signature stored inthe card or computing a certain 
 *  commitment.
 *
 *  By now the constructor expects a certain credential and
 *  the public key of the entity that issued it.
 */

package com.ibm.zurich.idmx.buildingBlock.signature.cl;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.lang.Integer;
import java.util.Arrays;
import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;

import eu.abc4trust.xml.PublicKey;
import eu.abc4trust.xml.SignatureToken;
import eu.abc4trust.xml.SystemParameters;

import java.util.List;
import javax.smartcardio.*;
    
import com.ibm.zurich.idmx.annotations.Nullable;
import com.ibm.zurich.idmx.buildingBlock.factory.BuildingBlockFactory;
import com.ibm.zurich.idmx.buildingBlock.helper.BaseForRepresentation;
import com.ibm.zurich.idmx.buildingBlock.helper.representation.damgardFujisaki.DamgardFujisakiRepresentationBuildingBlock;
import com.ibm.zurich.idmx.buildingBlock.systemParameters.EcryptSystemParametersWrapper;
import com.ibm.zurich.idmx.configuration.Configuration;
import com.ibm.zurich.idmx.exception.ConfigurationException;
import com.ibm.zurich.idmx.exception.ProofException;
import com.ibm.zurich.idmx.interfaces.device.ExternalSecretsManager;
import com.ibm.zurich.idmx.interfaces.util.BigInt;
import com.ibm.zurich.idmx.interfaces.util.BigIntFactory;
import com.ibm.zurich.idmx.interfaces.util.RandomGeneration;
import com.ibm.zurich.idmx.interfaces.util.group.GroupElement;
import com.ibm.zurich.idmx.interfaces.util.group.GroupFactory;
import com.ibm.zurich.idmx.interfaces.util.group.HiddenOrderGroup;
import com.ibm.zurich.idmx.interfaces.util.group.HiddenOrderGroupElement;
import com.ibm.zurich.idmx.interfaces.zkModule.ZkModuleProver;
import com.ibm.zurich.idmx.interfaces.zkModule.ZkModuleProverCommitment;
import com.ibm.zurich.idmx.interfaces.zkModule.state.ZkProofStateCollect;
import com.ibm.zurich.idmx.interfaces.zkModule.state.ZkProofStateFirstRound;
import com.ibm.zurich.idmx.interfaces.zkModule.state.ZkProofStateInitialize;
import com.ibm.zurich.idmx.interfaces.zkModule.state.ZkProofStateSecondRound;
import com.ibm.zurich.idmx.zkModule.ZkModuleImpl;
import com.ibm.zurich.idmx.util.bigInt.BigIntFactoryImpl;

public class Irma {

  /* This objects are used during the communication with
     the smartcard */
  private List<CardTerminal> terminals;
  private CardTerminal terminal;
  private TerminalFactory factory;
  private Card card;
  private ResponseAPDU rAPDU;
  private CardChannel channel;
  private BigIntFactory bigIntFactory;

  private IrmaLoader irmaLoader; /* This class parses and processes the XML
  description of a certain issuer public keys and a credential issued by it */

  private static final String SW_OK = "9000"; /* Operation OK in the smart card */

  /* Constant representations of the APDUs that are used in the IRMA card for interacting
  with ABC4Trust */

  private static final byte[] selectAPDU = {(byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, (byte)0x09, (byte)0xF8,
                                            (byte)0x49, (byte)0x52, (byte)0x4D, (byte)0x41, (byte)0x63, (byte)0x61,
                                            (byte)0x72, (byte)0x64, (byte)0x18}; /* This APDU selects the IRMA app
                                            in the smart card*/

  private static final byte[] getSAPDU = {(byte)0x80,(byte)0x5B,(byte)0x04,(byte)0x00}; /* This APDU retrieves the S base
  of the issuer public key */
  private static final byte[] getZAPDU = {(byte)0x80,(byte)0x5B,(byte)0x03,(byte)0x00}; /* This APDU retrieves the Z base 
  of the issuer public key */
  private static final byte[] getAAPDU = {(byte)0x80, (byte)0x5D, (byte)0x00, (byte)0x00}; /* This APDU retrieves the A
  component of the CL signature (A, e, v) */
  private static final byte[] getEAPDU = {(byte)0x80, (byte)0x5D, (byte)0x01, (byte)0x00}; /* This APDU retrieves the e component
  of the CL signature (A, e, v)*/
  
  private static final byte[] getRdAPDU = {(byte)0x80, (byte)0x5B, (byte)0x01, (byte)0x00}; /* This APDU retrieves the Rd base
  of the issuer public key */
  private static final byte[] getRsAPDU = {(byte)0x80, (byte)0x5B, (byte)0x00, (byte)0x00}; /* This APDU retrieves the Rs base
  of the issuer public key */
  private static final byte[] getR0APDU = {(byte)0x80, (byte)0x5A, (byte)0x00, (byte)0x00}; /* This APDU retrieves the R0 base
  of the issuer public key */
  private static final byte[] getR1APDU = {(byte)0x80, (byte)0x5A, (byte)0x01, (byte)0x00}; /* This APDU retrieves the R1 base
  of the issuer public key */
  private static final byte[] getR2APDU = {(byte)0x80, (byte)0x5A, (byte)0x02, (byte)0x00}; /* This APDU retrieves the R2 base
  of the issuer public key */
  private static final byte[] getR3APDU = {(byte)0x80, (byte)0x5A, (byte)0x03, (byte)0x00}; /* This APDU retrieves the R3 base 
  of the issuer public key */
  private static final byte[] getR4APDU = {(byte)0x80, (byte)0x5A, (byte)0x04, (byte)0x00}; /* This APDU retrieves the R4 base
  of the issuer public key */

  private static final byte[] randomizeAAPDU = {(byte)0x80, (byte)0x5E, (byte)0x00, (byte)0x00}; /* This APDU randomizes the A
  component the CL signature stored in the card */

  private static final byte[] randomizeVAPDU = {(byte)0x80, (byte)0x5F, (byte)0x00, (byte)0x00}; /* This APDU randomizes the V
  component of the CL signature stored in the card */

  private static final byte[]  setR0APDU = {(byte)0x80, (byte)0x4A, (byte)0x00, (byte)0x00, (byte)0x80}; /* This APDU sets the value
  of the base R0 */
  private static final byte[]  setR1APDU = {(byte)0x80, (byte)0x4A, (byte)0x01, (byte)0x00, (byte)0x80}; /* This APDU sets the value
  of the base R1 */
  private static final byte[]  setR2APDU = {(byte)0x80, (byte)0x4A, (byte)0x02, (byte)0x00, (byte)0x80}; /* This APDU sets the value
  of the base R2 */
  private static final byte[]  setR3APDU = {(byte)0x80, (byte)0x4A, (byte)0x03, (byte)0x00, (byte)0x80}; /* This APDU sets the value
  of the base R3 */
  private static final byte[]  setR4APDU = {(byte)0x80, (byte)0x4A, (byte)0x04, (byte)0x00, (byte)0x80}; /* This APDU sets the value
  of the base R4 */
  private static final byte[]  setR5APDU = {(byte)0x80, (byte)0x4A, (byte)0x05, (byte)0x00, (byte)0x80}; /* This APDU sets the value
  of the base R5 */

  private static final byte[]  setIPK0APDU = {(byte)0x80, (byte)0x4B, (byte)0x00, (byte)0x00, (byte)0x80}; /* This APDU sets the value
  of the base Rt */
  private static final byte[]  setIPK1APDU = {(byte)0x80, (byte)0x4B, (byte)0x01, (byte)0x00, (byte)0x80}; /* This APDU sets the value
  of the base Rd */
  private static final byte[]  setIPK2APDU = {(byte)0x80, (byte)0x4B, (byte)0x02, (byte)0x00, (byte)0x80}; /* This APDU sets the value
  of the modulus */
  private static final byte[]  setIPK3APDU = {(byte)0x80, (byte)0x4B, (byte)0x03, (byte)0x00, (byte)0x80}; /* This APDU sets the value
  of the base Z */
  private static final byte[]  setIPK4APDU = {(byte)0x80, (byte)0x4B, (byte)0x04, (byte)0x00, (byte)0x80}; /* This APDU sets the value
  of the base S */

  /* These are the APDUs for setting the value of the attributes of a given credential. These APDUs are not
  used in the key binding use case. They are reused here for uploading the pseudonym parameters. */
  private static final byte[]  setATTR0APDU = {(byte)0x80, (byte)0x4C, (byte)0x00, (byte)0x00, (byte)0x80}; // baseNym
  private static final byte[]  setATTR1APDU = {(byte)0x80, (byte)0x4C, (byte)0x01, (byte)0x00, (byte)0x80}; // dhGen1 
  private static final byte[]  setATTR2APDU = {(byte)0x80, (byte)0x4C, (byte)0x02, (byte)0x00, (byte)0x80}; // modNym
  private static final byte[]  setATTR3APDU = {(byte)0x80, (byte)0x4C, (byte)0x03, (byte)0x00, (byte)0x20};
  private static final byte[]  setATTR4APDU = {(byte)0x80, (byte)0x4C, (byte)0x04, (byte)0x00, (byte)0x20};
  private static final byte[]  setATTR5APDU = {(byte)0x80, (byte)0x4C, (byte)0x05, (byte)0x00, (byte)0x20};

  private static final byte[]  setSIG0APDU = {(byte)0x80, (byte)0x4D, (byte)0x00, (byte)0x00, (byte)0x80}; /* This APDU sets the value
  of the A component of a CL signature */
  private static final byte[]  setSIG1APDU = {(byte)0x80, (byte)0x4D, (byte)0x01, (byte)0x00, (byte)0x4B}; /* This APDU sets the value
  of the e component of a CL signature */
  private static final byte[]  setSIG2APDU = {(byte)0x80, (byte)0x4D, (byte)0x02, (byte)0x00, (byte)0xD5}; /* This APDU sets the value
  of the v component of a CL signature */

  private static final byte[]  getNYMAPDU = {(byte)0x80, (byte)0x50, (byte)0x00, (byte)0x00}; /* This APDU retrieves the value
  of the commitment related to a limited scope pseudonym */
  private static final byte[]  getCOMAPDU = {(byte)0x80, (byte)0x51, (byte)0x00, (byte)0x00}; /* This APDU retrieves the value
  of the commitment T = Rd^{r_1} Rd^{r_2} (where $r_1, r_2$ are pseudorandom numbers) related to the key binding use case */

  private static final byte[]  getS1APDU = {(byte)0x80, (byte)0x52, (byte)0x00, (byte)0x00, (byte)0x20}; /* This APDU retrieves
  the first s-value related to the key binding use case */
  private static final byte[]  getS2APDU = {(byte)0x80, (byte)0x53, (byte)0x00, (byte)0x00, (byte)0x20}; /* This APDU retrieves
  the second s-value related to the key binding use case */
  private static final byte[]  getPKCOMAPDU = {(byte)0x80, (byte)0x54, (byte)0x00, (byte)0x00, (byte)0x20}; /* This APDU retrieves
  a public key commitment computed on card */ 
  private static final byte[]  genRANDOMAPDU = {(byte)0x80, (byte)0x55, (byte)0x00, (byte)0x00, (byte)0x20}; /* This APDU generates
  the pseudorandomness associated to $r_1, r_2$ */

  private static final byte[]  setDHGENAPDU = {(byte)0x80, (byte)0x6A, (byte)0x00, (byte)0x00, (byte)0x80}; /* This APDU sets
  the value of the first DH generator */
  private static final byte[]  setDHMODAPDU = {(byte)0x80, (byte)0x57, (byte)0x00, (byte)0x00, (byte)0x80}; /* This APDU sets
  the DH modulus */
  private static final byte[]  setNYMBASEAPDU = {(byte)0x80, (byte)0x58, (byte)0x00, (byte)0x00, (byte)0x81}; /* This APDU sets
  the base utilized for limited scope pseudonyms */

  public Irma () {
    this.terminals = null;
    this.terminal = null;
    this.factory = null;
    this.card = null;
    this.rAPDU = null;
    this.channel = null;
    this.irmaLoader = null;
    
    bigIntFactory = new BigIntFactoryImpl();
  }
  
  /** 
   * This method expects the path to a certain issuer CL public key
   * together with the path of a given credential issued by her.
   * These files are then used for loading the required parameters
   * in the IRMA card for performing different operations on the 
   * card.
   *
   * @param none.
   * @return none.
   */
  public void setLoader(String issuerPublicKeyPath, String credentialPath, String systemParametersPath, String presentationPolicy) {
    irmaLoader = new IrmaLoader(issuerPublicKeyPath, credentialPath, systemParametersPath, presentationPolicy);  
  }
  
  /**
   * This method loads a triple (A, e, v) to the smart card.
   *
   * @param none.
   * @return true if the triple was correctly uploaded.
   */
  public boolean uploadClSignature() {
    
    if (irmaLoader == null)
     return false;
    
    if (!irmaLoader.processClSignature())
     return false;
  
    /* We transform the big integer representation of each component
    of the signature into the correct APDU that upload such value */
    String aString = irmaLoader.getA().getValue().toString(16); 
    String eString = irmaLoader.getE().getValue().toString(16);
    String vString = irmaLoader.getV().getValue().toString(16);

    byte[] a = new BigInteger(aString, 16).toByteArray();
    byte[] e = new BigInteger(eString, 16).toByteArray();
    byte[] v = new BigInteger(vString, 16).toByteArray();

    byte[] a_apdu = new byte[a.length + setSIG0APDU.length];
    byte[] e_apdu = new byte[e.length + setSIG1APDU.length];
    byte[] v_apdu = new byte[v.length + setSIG2APDU.length];

    System.arraycopy(setSIG0APDU, 0, a_apdu, 0, setSIG0APDU.length);
    System.arraycopy(a, 0, a_apdu, setSIG0APDU.length, a.length);

    System.arraycopy(setSIG1APDU, 0, e_apdu, 0, setSIG1APDU.length);
    System.arraycopy(e, 0, e_apdu, setSIG1APDU.length, e.length);

    System.arraycopy(setSIG2APDU, 0, v_apdu, 0, setSIG2APDU.length);
    System.arraycopy(v, 0, v_apdu, setSIG2APDU.length, v.length);

    ResponseAPDU resp = sendAPDU(a_apdu);
    if (!Integer.toHexString(resp.getSW()).equals(SW_OK))   
     return false;
    
    resp = sendAPDU(e_apdu);
    if (!Integer.toHexString(resp.getSW()).equals(SW_OK))   
     return false;

    resp = sendAPDU(v_apdu);
    if (!Integer.toHexString(resp.getSW()).equals(SW_OK))   
     return false;

   return true;
  }

  /**
   * This method loads the modulus and the $Rd, S$ bases into the smart card.
   *
   * @param none.
   * @return true if the values were correctly uploaded.
   */
  public boolean uploadClPublicKey() {
    if (irmaLoader == null)
     return false;

    if (!irmaLoader.processClPublicKey())
     return false;

    String modulusString = irmaLoader.getModulus().getValue().toString(16);
    String dString = irmaLoader.getD().getValue().toString(16);
    String sString = irmaLoader.getS().getValue().toString(16);

    byte[] modulus = new BigInteger(modulusString, 16).toByteArray();
    byte[] d = new BigInteger(dString, 16).toByteArray();
    byte[] s = new BigInteger(sString, 16).toByteArray();

    byte[] modulus_apdu = new byte[modulus.length + setIPK2APDU.length];
    byte[] d_apdu = new byte[d.length + setIPK1APDU.length];
    byte[] s_apdu = new byte[s.length + setIPK4APDU.length];

    Byte b = modulus[0];

    if (b.intValue() == 0)
     modulus = Arrays.copyOfRange(modulus, 1, modulus.length);
    
    System.arraycopy(setIPK2APDU, 0, modulus_apdu, 0, setIPK2APDU.length);
    System.arraycopy(modulus, 0, modulus_apdu, setIPK2APDU.length, modulus.length);

    b = d[0];

    if (b.intValue() == 0)
     d = Arrays.copyOfRange(d, 1, d.length);

    System.arraycopy(setIPK1APDU, 0, d_apdu, 0, setIPK1APDU.length);
    System.arraycopy(d, 0, d_apdu, setIPK1APDU.length, d.length);

    b = s[0];

    if (b.intValue() == 0)
     s = Arrays.copyOfRange(s, 1, s.length);

    System.arraycopy(setIPK4APDU, 0, s_apdu, 0, setIPK4APDU.length);
    System.arraycopy(s, 0, s_apdu, setIPK4APDU.length, s.length);

    ResponseAPDU resp = sendAPDU(modulus_apdu);
    if (!Integer.toHexString(resp.getSW()).equals(SW_OK))   
     return false;
     
    resp = sendAPDU(d_apdu);
    if (!Integer.toHexString(resp.getSW()).equals(SW_OK))   
     return false;

    resp = sendAPDU(s_apdu);
    if (!Integer.toHexString(resp.getSW()).equals(SW_OK))   
     return false;

   return true;
  
  }

  /**
   * This method loads the required parameters (dhgen1, dhmodulus and a base)
   * for performing limited scope pseudonyms and public key commitments on the
   * smart card.
   *
   * @param none.
   * @return true if the values were correctly uploaded.
   */
  public boolean uploadSystemParameters() {

    if (irmaLoader == null)
     return false;

    if (!irmaLoader.processSystemParameters())
     return false;

    if (!irmaLoader.processPresentationPolicy())
     return false;

    String dhgen1String = irmaLoader.getDHGen1().getValue().toString(16);
    String nymBaseString = irmaLoader.getNymBase().getValue().toString(16);
    String dhModulusString = irmaLoader.getDhModulus().getValue().toString(16);

    byte[] dhgen1 = new BigInteger(dhgen1String, 16).toByteArray();
    byte[] nymBase = new BigInteger(nymBaseString, 16).toByteArray();
    byte[] dhModulus = new BigInteger(dhModulusString, 16).toByteArray();

    Byte b = dhModulus[0];
    
    if (b.intValue() == 0)
     dhModulus = Arrays.copyOfRange(dhModulus, 1, dhModulus.length);

    byte[] dhgen1_apdu = new byte[dhgen1.length + setATTR1APDU.length];
    byte[] nymBase_apdu = new byte[nymBase.length + setATTR0APDU.length];
    byte[] dhModulus_apdu = new byte[dhModulus.length + setATTR2APDU.length];

    System.arraycopy(setATTR0APDU, 0, nymBase_apdu, 0, setATTR0APDU.length);
    System.arraycopy(nymBase, 0, nymBase_apdu, setATTR0APDU.length, nymBase.length);

    System.arraycopy(setATTR1APDU, 0, dhgen1_apdu, 0, setATTR1APDU.length);
    System.arraycopy(dhgen1, 0, dhgen1_apdu, setATTR1APDU.length, dhgen1.length);

    System.arraycopy(setATTR2APDU, 0, dhModulus_apdu, 0, setATTR2APDU.length);
    System.arraycopy(dhModulus, 0, dhModulus_apdu, setATTR2APDU.length, dhModulus.length);

    ResponseAPDU resp = sendAPDU(nymBase_apdu);
    if (!Integer.toHexString(resp.getSW()).equals(SW_OK)) 
     return false;
      
    resp = sendAPDU(dhgen1_apdu);
    if (!Integer.toHexString(resp.getSW()).equals(SW_OK)) 
     return false;

    resp = sendAPDU(dhModulus_apdu);
    if (!Integer.toHexString(resp.getSW()).equals(SW_OK)) 
     return false;
     
   return true;  
  }

  /**
   * This method obtains a list of smart card terminals connected
   * to the cardholder's PC.
   *
   * @param none
   * @return the list of detected terminals.
   */
  public List<CardTerminal> getTerminalList() {
   try {
    this.factory = TerminalFactory.getDefault();
    this.terminals = factory.terminals().list();   
   
    return terminals;
   
   } catch(CardException e) {
    System.out.println("getTerminalList(): " + e);
    return null;
   }
  }

  /**
   * This method performs the connection to a certain terminal and
   * returns the associated channel handle.
   *
   * @param the selected terminal.
   * @return the channel handle or null otherwise.
   */
  public CardChannel getChannel(CardTerminal terminal) {
   try {
    card = terminal.connect("*");
     
    channel = card.getBasicChannel();
 
    return channel;
   } catch(CardException e) {
    System.out.println("getChannel(): " + e);
    return null;
   }
  }

  /**
   * This method sends the SELECT APDU to the smart card
   * for selecting the IRMA application.
   *
   * @param a smart card communication channel.
   * @return true if the IRMA application was detected.
   */
  public boolean connectToIrma(CardChannel channel) {
   this.channel = channel;

   ResponseAPDU resp = sendAPDU(this.selectAPDU);

   if (Integer.toHexString(resp.getSW()).equals(SW_OK))   
    return true;
   else
    return false;    
  }
  
  /**
   * This method retrieves the S base of the issuer public
   * key.
   *
   * @param none.
   * @return the S base of the issuer public key.
   */
  public BigInt getS() {
   return getParameter(this.getSAPDU);
  }

  /**
   * This method retrieves the Z base of the issuer public
   * key.
   *
   * @param none.
   * @return the S base of the issuer public key.
   */
  public BigInt getZ() {
   return getParameter(this.getZAPDU);
  }

  /**
   * This method retrieves the A component of the CL 
   * signature.
   *
   * @param none.
   * @return the S base of the issuer public key.
   */
  public BigInt getA() {
   return getParameter(this.getAAPDU);
  }

  /**
   * This method retrieves the S base of the issuer public
   * key.
   *
   * @param none.
   * @return the S base of the issuer public key.
   */
  public BigInt getE() {
   return getParameter(this.getEAPDU);
  }

  /**
   * This method retrieves the Rd base of the issuer public
   * key.
   *
   * @param none.
   * @return the Rd base of the issuer public key.
   */
  public BigInt getRd() {
   return getParameter(this.getRdAPDU);
  }

  /**
   * This method retrieves the Rs base of the issuer public
   * key.
   * @param none.
   * @return the Rs base of the issuer public key.
   */
  public BigInt getRs() {
   return getParameter(this.getRsAPDU);
  }

  /**
   * This method retrieves the R0 base of the issuer public
   * key.
   *
   * @param none.
   * @return the R0 base of the issuer public key.
   */
  public BigInt getR0() {
   return getParameter(this.getR0APDU);
  }

  /**
   * This method retrieves the R1 base of the issuer public
   * key.
   * @param none.
   * @return the R1 base of the issuer public key.
   */
  public BigInt getR1() {
   return getParameter(this.getR1APDU);
  }

  /**
   * This method retrieves the R2 base of the issuer public
   * key.
   *
   * @param none.
   * @return the R2 base of the issuer public key.
   */
  public BigInt getR2() {
   return getParameter(this.getR2APDU);
  }

  /**
   * This method retrieves the R3 base of the issuer public
   * key.
   * @param none
   * @return the R3 base of the issuer public key
   */
  public BigInt getR3() {
   return getParameter(this.getR3APDU);
  }

  /**
   * This method retrieves the R4 base of the issuer public
   * key.
   *
   * @param none.
   * @return the R4 base of the issuer public key.
   */
  public BigInt getR4() {
   return getParameter(this.getR4APDU);
  }

  /**
   * This method retrieves the commitment related to a limited
   * scope pseudonym computed by the card.
   * key.
   *
   * @param none
   * @return the commitment
   */
  public BigInt getNYM() {
   return getParameter(this.getNYMAPDU);
  }

  /**
   * This method retrieves the commitment T related to
   * the key binding use case.
   * key.
   *
   * @param none.
   * @return the T commitment.
   */
  public BigInt getCOM() {
   return getParameter(this.getCOMAPDU);
  }

  /**
   * This method retrieves the first s-value of the key binding
   * use case.
   *
   * @param none
   * @return the first s-value
   */
  public BigInt getS1(BigInt challenge) {
   return getParameter(this.getS1APDU, challenge);
  }

  /**
   * This method retrieves the second s-value of the key binding
   * use case.
   *
   * @param none.
   * @return the second s-value.
   */
  public BigInt getS2(BigInt challenge) {
   return getParameter(this.getS2APDU, challenge);
  }

  /**
   * This method randomizes the component A of the CL triple
   * stored in the card and retrieves such value.
   *
   * @param none.
   * @return the randomized A component.
   */
  public BigInt randomizeA() {
   return getParameter(this.randomizeAAPDU);
  }

  /**
   * This method randomizes the component V of the CL triple
   * stored in the card and retrieves such value.
   *
   * @param none.
   * @return the randomized V component.
   */
  public BigInt randomizeV() {
   return getParameter(this.randomizeVAPDU);
  }

  /**
   * This method computes and retrieve a public key 
   * commitment on the card.
   *
   * @param none.
   * @return the public key commitment.
   */
  public BigInt getPKCOM() {
   return getParameter(this.getPKCOMAPDU);
  }

  /**
   * This method generates the pseudoramdon values $r1, r2$ associated
   * to the key binding use case.
   *
   * @param none.
   * @return none.
   */
  public void genRANDOM() {
   ResponseAPDU resp = sendAPDU(this.genRANDOMAPDU);
  }

  /**
   * This method send a certain APDU to the IRMA card.
   *
   * @param the APDU.
   * @return the response APDU.
   */
  private ResponseAPDU sendAPDU(byte[] apdu) {
   try {
    return this.channel.transmit(new CommandAPDU(apdu));
   } catch(CardException e) {
    System.out.println("sendAPDU(): " + e);
    return null;
   }
  }

  /**
   * This method retrieves the answer of an APDU that channels
   * a Big Int value back.
   *
   * @param the APDU.
   * @return the result of the operation sent by the smart card.
   */
  private BigInt getParameter(byte[] apdu) {

   ResponseAPDU resp = sendAPDU(apdu);
   String string = DatatypeConverter.printHexBinary(resp.getData());
   
   BigInteger nt = new BigInteger(string, 16);

   return bigIntFactory.valueOf(nt);    
  }

  /**
   * This method retrieves the answer of an APDU that channels
   * a Big Int value back. However, in this case it also sends
   * the challenge c to the smart card for computing a certain s-value.
   * This approach is required since the card cannot compute the challenge
   * by itself given that the generation of that value is centralized
   * by the Idemix implementation.
   *
   * @param the APDU.
   * @return the result of the operation sent by the smart card (s-value).
   */
  private BigInt getParameter(byte[] apdu, BigInt challenge) {

   String cString = challenge.getValue().toString(16);

   byte[] cByteArray = new BigInteger(cString, 16).toByteArray();
   byte[] cAPDU = new byte[apdu.length + cByteArray.length];

   System.arraycopy(apdu, 0, cAPDU, 0, apdu.length);
   System.arraycopy(cByteArray, 0, cAPDU, apdu.length, cByteArray.length);

   ResponseAPDU resp = sendAPDU(cAPDU);
   String string = DatatypeConverter.printHexBinary(resp.getData());
        
   BigInteger nt = new BigInteger(string, 16);
   return bigIntFactory.valueOf(nt);  
  }

private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
public static String bytesToHex(byte[] bytes) {
    char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
                int v = bytes[j] & 0xFF;
                        hexChars[j * 2] = hexArray[v >>> 4];
                                hexChars[j * 2 + 1] = hexArray[v & 0x0F];
                                    }
                                        return new String(hexChars);
                                        }

}
