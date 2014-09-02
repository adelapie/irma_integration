/**
 *  This class processes issuers CL public keys and
 *  credentials described according to the ABC4Trust
 *  scheme. Then, those values are loaded in the
 *  IRMA card via the Irma.java class.
 */
  
package com.ibm.zurich.idmx.buildingBlock.signature.cl;

import com.ibm.zurich.idmx.annotations.Nullable;
import com.ibm.zurich.idmx.configuration.Configuration;
import com.ibm.zurich.idmx.configuration.ErrorMessages;
import com.ibm.zurich.idmx.exception.ConfigurationException;
import com.ibm.zurich.idmx.exception.NotEnoughTokensException;
import com.ibm.zurich.idmx.exception.SerializationException;
import com.ibm.zurich.idmx.interfaces.configuration.Constants;
import com.ibm.zurich.idmx.interfaces.signature.ListOfSignaturesAndAttributes;
import com.ibm.zurich.idmx.interfaces.state.CarryOverStateRecipientWithAttributes;
import com.ibm.zurich.idmx.interfaces.util.BigInt;
import com.ibm.zurich.idmx.interfaces.util.BigIntFactory;
import com.ibm.zurich.idmx.util.bigInt.BigIntFactoryImpl;

import com.ibm.zurich.idmx.jaxb.JaxbHelperClass;
import com.ibm.zurich.idmix.abc4trust.facades.IssuerParametersFacade;
import com.ibm.zurich.idmx.parameters.system.SystemParametersWrapper;
import com.ibm.zurich.idmx.buildingBlock.systemParameters.EcryptSystemParametersWrapper;
import com.ibm.zurich.idmx.deviceMock.ExternalSecretsHelperMock;


import eu.abc4trust.abce.internal.user.credentialManager.CredentialManager;
import eu.abc4trust.abce.internal.user.credentialManager.CredentialManagerException;

import eu.abc4trust.util.AttributeConverter;

import eu.abc4trust.xml.Attribute;
import eu.abc4trust.xml.AttributeDescription;
import eu.abc4trust.xml.Credential;
import eu.abc4trust.xml.IssuerParameters;
import eu.abc4trust.xml.SystemParameters;
import eu.abc4trust.xml.CredentialDescription;
import eu.abc4trust.xml.CredentialSpecification;
import eu.abc4trust.xml.CredentialTemplate;
import eu.abc4trust.xml.CryptoParams;
import eu.abc4trust.xml.FriendlyDescription;
import eu.abc4trust.xml.NonRevocationEvidence;
import eu.abc4trust.xml.ObjectFactory;
import eu.abc4trust.xml.PresentationToken;
import eu.abc4trust.xml.PresentationTokenDescription;
import eu.abc4trust.xml.PublicKey;
import eu.abc4trust.xml.Signature;
import eu.abc4trust.xml.SignatureToken;

import java.io.InputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Scanner;
import java.math.BigInteger;
import java.net.URI;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBIntrospector;

public class IrmaLoader {

  private Credential credential; /* The deserialized representation of the
                                  * given credential. */

  private BigInt A; /* The A component from the CL triple (A, e,v) */
  private BigInt e; /* The e component from the CL triple (A, e,v) */
  private BigInt v; /* The v component from the CL triple (A, e,v) */

  private BigInt S; /* The base S from the issuer CL public key */
  private BigInt D; /* The base Rd from the issuer CL public key */
  private BigInt modulus; /* The public key modulus */

  private BigInt dhGen1; /* First DH generator */
  private BigInt dhModulus; /* Modulus for limited scope pseudonyms */
  
  private BigInt nymBase; /* Base for pseudonyms of limited scope */
  private BigInt dhSubgroupOrder; /* The order of the DH subgroup is
  required for computing nymBase */
  
  private IssuerParameters issuerParameters; /* Deserialized representation of the
  issuing parameters */
  private SystemParameters systemParameters; /* Deserialized representation of the
  system parameters */
  private PresentationTokenDescription presentationTokenDescription; /* Deserialized
  representation of the presentation token */

  /**
   * In the constructor, the given issuer CL public key and the credential 
   * description are deserialized and loaded in the Credential attribute of
   * the class. Moreover, a description of the system parameters is also
   * expected in order to load the required parameters for performing
   * limited scope pseudonyms on the card.
   */
  public IrmaLoader(String issuerPublicKeyPath, String credentialPath, String systemParametersPath, String presentationPolicy) {

    issuerParameters = null;

    try {
      InputStream resource = new FileInputStream(new File(credentialPath));
      JAXBElement<?> resourceAsJaxbElement = JaxbHelperClass.deserialize(resource, true);
      this.credential = (Credential)JAXBIntrospector.getValue(resourceAsJaxbElement);

      resource = new FileInputStream(new File(issuerPublicKeyPath));
      resourceAsJaxbElement = JaxbHelperClass.deserialize(resource, true);
      this.issuerParameters = (IssuerParameters)JAXBIntrospector.getValue(resourceAsJaxbElement);

      resource = new FileInputStream(new File(systemParametersPath));
      resourceAsJaxbElement = JaxbHelperClass.deserialize(resource, true);
      this.systemParameters = (SystemParameters)JAXBIntrospector.getValue(resourceAsJaxbElement);

      resource = new FileInputStream(new File(presentationPolicy));
      resourceAsJaxbElement = JaxbHelperClass.deserialize(resource, true);
      PresentationToken presentationToken = (PresentationToken)JAXBIntrospector.getValue(resourceAsJaxbElement);
      this.presentationTokenDescription = presentationToken.getPresentationTokenDescription();

    } catch(SerializationException e) {
      System.out.println("IrmaLoader() - It was impossible to deserialize XML input: " + e);
      System.exit(-1);
    } catch (FileNotFoundException e) {
      System.out.println("IrmaLoader() - It was impossible to open the given XML file: " + e);
      System.exit(-1);
    }
  }

  /**
   * This method retrieves the (A, e, v) triple from the
   * credential description.
   *
   * @param none.
   * @return true if the triple was found and processed.
   */
  public boolean processClSignature() {
    try {
 
      CryptoParams cryptoParams = this.credential.getCryptoParams();
      List<Object> cryptoParameterList =  cryptoParams.getAny();
    
      for (Object object : cryptoParameterList) {
        Object containedObject = JAXBIntrospector.getValue(object);

        if ((Signature.class).isAssignableFrom(containedObject.getClass())) {
 
          Signature sig = (Signature)containedObject; 
          SignatureToken signatureToken = sig.getSignatureToken().get(0);

          ClSignatureTokenWrapper st = new ClSignatureTokenWrapper(signatureToken);
      
          this.A = st.getA();
          this.e = st.getE();
          this.v = st.getV();
      
          return true;
        }
      }
      return false;

    } catch(ConfigurationException e) {
      System.out.println("processClSignature(): " + e);

      return false;
    }
  }

  /**
   * This method retrieves the issuer parameters from a
   * certain description of a CL public key.
   *
   * @param none.
   * @return true if the parameters were found and processed.
   */
  public boolean processClPublicKey() {

    IssuerParametersFacade ipFacade = new IssuerParametersFacade(issuerParameters);
    PublicKey ip = ipFacade.getPublicKey();

    try {

      ClPublicKeyWrapper pkw = new ClPublicKeyWrapper(ip);                    

      this.modulus = pkw.getModulus();
      this.D = pkw.getRd();
      this.S = pkw.getS();

      return true;

    } catch (ConfigurationException e) {
      System.out.println("processClPublicKey(): " + e);

      return false;
    }
  }

  /**
   * This method retrieves two parameters (dhGen1 and dhModulus)
   * required for performing pseudonyms on the smart card.
   *
   * @param none.
   * @return true if the parameters were found and processed.
   */
  public boolean processSystemParameters() {
      
    try {
      EcryptSystemParametersWrapper spWrapper = new EcryptSystemParametersWrapper(this.systemParameters);

      this.dhGen1 = spWrapper.getDHGenerator1();
      this.dhModulus = spWrapper.getDHModulus();
      this.dhSubgroupOrder = spWrapper.getDHSubgroupOrder();

      return true;

    } catch (ConfigurationException e) {
      System.out.println("processSystemParameters(): " + e);

      return false;
    }
  }

  /**
   * This method retrieves (if any) the scope of a limited
   * scope pseudonym from a certain presentation policy.
   *
   * @param none.
   * @return true if the parameters were found and processed.
   */
  public boolean processPresentationPolicy() {
      
    String scope = this.presentationTokenDescription.getPseudonym().get(0).getScope();
    BigIntFactory bigIntFactory = new BigIntFactoryImpl();
      
    try {
      this.nymBase = ExternalSecretsHelperMock.getBaseForScopeExclusivePseudonym(bigIntFactory, new URI(scope), this.dhModulus,
        this.dhSubgroupOrder);

    } catch (URISyntaxException e) {
      System.out.println("processPresentationPolicy(): " + e);
      
      return false;
    }             

    return true;
  }

  /**
   * This method retrieves the A component of the CL signature
   * over a certain credential.
   *
   * @param none.
   * @return the A component of a certain (A, e, v) triple.
   */
  public BigInt getA() {
    return this.A;
  }

  /**
   * This method retrieves the e component of the CL signature
   * over a certain credential.
   *
   * @param none.
   * @return the e component of a certain (A, e, v) triple.
   */
  public BigInt getE() {
    return this.e;
  }

  /**
   * This method retrieves the v component of the CL signature
   * over a certain credential.
   *
   * @param none.
   * @return the v component of a certain (A, e, v) triple.
   */
  public BigInt getV() {
    return this.v;
  }

  /**
   * This method retrieves the modulus of the CL public key.
   *
   * @param none.
   * @return the modulus.
   */
  public BigInt getModulus() {
    return this.modulus;
  }

  /**
   * This method retrieves the base Rd of the CL public key.
   *
   * @param none.
   * @return the base Rd.
   */
  public BigInt getD() {
    return this.D;
  }

  /**
   * This method retrieves the base S of the CL public key.
   * @param none
   * @return the base S.
   */
  public BigInt getS() {
    return this.S;
  }

  /**
   * This method retrieves the first DH generator from the
   * system parameters.
   * @param none
   * @return the first DH generator.
   */
  public BigInt getDHGen1() {
    return this.dhGen1;
  }

  /**
   * This method retrieves the DH modulus utilized in the
   * computation of limited scope pseudonyms.
   * @param none
   * @return the DH modulus.
   */
  public BigInt getDhModulus() {
    return this.dhModulus;
  }

  /**
   * This method retrieves the base for computing 
   * limited scope pseudonyms on the smart card.
   * @param none
   * @return the base utilized for computing
   * limited scope pseudonyms.
   */
  public BigInt getNymBase() {
    return this.nymBase;
  }
}


