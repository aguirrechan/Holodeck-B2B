/**
 * Copyright (C) 2014 The Holodeck B2B Team, Sander Fieten
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.holodeckb2b.ebms3.pmode;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;

import org.apache.logging.log4j.Logger;

import org.holodeckb2b.common.util.CompareUtils;
import org.holodeckb2b.commons.util.Utils;
import org.holodeckb2b.core.pmode.PModeUtils;
import org.holodeckb2b.interfaces.core.HolodeckB2BCoreInterface;
import org.holodeckb2b.interfaces.general.EbMSConstants;
import org.holodeckb2b.interfaces.general.IAgreement;
import org.holodeckb2b.interfaces.general.IPartyId;
import org.holodeckb2b.interfaces.general.IProperty;
import org.holodeckb2b.interfaces.general.IService;
import org.holodeckb2b.interfaces.general.ITradingPartner;
import org.holodeckb2b.interfaces.messagemodel.IAgreementReference;
import org.holodeckb2b.interfaces.messagemodel.IUserMessage;
import org.holodeckb2b.interfaces.pmode.IBusinessInfo;
import org.holodeckb2b.interfaces.pmode.IErrorHandling;
import org.holodeckb2b.interfaces.pmode.ILeg;
import org.holodeckb2b.interfaces.pmode.IPMode;
import org.holodeckb2b.interfaces.pmode.IPModeSet;
import org.holodeckb2b.interfaces.pmode.IProtocol;
import org.holodeckb2b.interfaces.pmode.IPullRequestFlow;
import org.holodeckb2b.interfaces.pmode.IReceiptConfiguration;
import org.holodeckb2b.interfaces.pmode.ISecurityConfiguration;
import org.holodeckb2b.interfaces.pmode.ISigningConfiguration;
import org.holodeckb2b.interfaces.pmode.IUserMessageFlow;
import org.holodeckb2b.interfaces.pmode.IUsernameTokenConfiguration;
import org.holodeckb2b.interfaces.security.ISecurityProcessingResult;
import org.holodeckb2b.interfaces.security.ISignatureProcessingResult;
import org.holodeckb2b.interfaces.security.IUsernameTokenProcessingResult;
import org.holodeckb2b.interfaces.security.SecurityHeaderTarget;
import org.holodeckb2b.interfaces.security.SecurityProcessingException;
import org.holodeckb2b.security.util.VerificationUtils;

/**
 * Is a helper class for finding the correct processing configuration for a {@see IMessageUnit}. This starts with
 * finding the P-Mode and within the P-Mode the correct leg and channel.
 * <p>The P-Mode specifies how the message unit should be processed and therefore is essential in the processing chain.
 * Because the P-Mode id might not be available during message processing the P-Mode must be found based on the
 * available message meta data.
 *
 * @author Sander Fieten (sander at holodeck-b2b.org)
 * @see IPMode
 */
public class PModeFinder {

	/**
     * Identifiers for the meta-data that is being used in the matching
     */
    protected static enum PARAMETERS {ID, FROM, FROM_ROLE, TO, TO_ROLE, SERVICE, ACTION, MPC, AGREEMENT, MSG_PROPERTY}

    /**
     * The weight for each of the parameters
     */
    protected static Map<PARAMETERS, Integer> MATCH_WEIGHTS; 
    static {
        final Map<PARAMETERS, Integer> aMap = new EnumMap<> (PARAMETERS.class);
        aMap.put(PARAMETERS.ID, 74);
        aMap.put(PARAMETERS.FROM, 14);
        aMap.put(PARAMETERS.FROM_ROLE, 4);
        aMap.put(PARAMETERS.TO, 14);
        aMap.put(PARAMETERS.TO_ROLE, 4);
        aMap.put(PARAMETERS.SERVICE, 10);
        aMap.put(PARAMETERS.ACTION, 10);
        aMap.put(PARAMETERS.MPC, 2);
        aMap.put(PARAMETERS.AGREEMENT, 2);
        aMap.put(PARAMETERS.MSG_PROPERTY, 1);

        MATCH_WEIGHTS = Collections.unmodifiableMap(aMap);
    }

    /**
     * Finds the P-Mode for a received <i>User Message</i> message unit.
     * <p>The ebMS specifications do not describe or recommend how the P-Mode for a user message should be determined,
     * see also <a href="https://issues.oasis-open.org/browse/EBXMLMSG-48">issue 48 in the OASIS TC issue tracker</a>.
     * In the issue two suggestions for matching the P-Mode are given. Based on these we compare the meta-data from the 
     * message with all P-Modes and return the best matching P-Mode.
     * <p>The following table shows the information that is used for matching and their importance (expressed as a 
     * weight). The match of a P-Mode is the sum of the weights for the elements that are equal to the corresponding 
     * P-Mode parameter. If there is a mismatch on any of the elements the P-Mode is considered as a mismatch, but if
     * no value if specified in the P-Mode the element is not considered and not scored.
     * <p><table border="1">
     * <tr><th>Element</th><th>Weight</th></tr>
     * <tr><td>PMode id</td><td>74</td></tr>
     * <tr><td>From Party Id's</td><td>14</td></tr>
     * <tr><td>From.Role</td><td>4</td></tr>
     * <tr><td>To Party Id's</td><td>14</td></tr>
     * <tr><td>To.Role</td><td>4</td></tr>
     * <tr><td>Service</td><td>10</td></tr>
     * <tr><td>Action</td><td>10</td></tr>
     * <tr><td>Agreement ref</td><td>2</td></tr>
     * <tr><td>MPC</td><td>2</td></tr>
     * <tr><td>Message Property</td><td>1</td></tr>
     * </table> </p>
     * <p>Because the 2-Way MEP can be governed by two 1-Way P-Modes this method will just check all P-Modes that govern
     * message receiving. It is up to the handlers to decide whether the result is acceptable or not. This method will 
     * only find one matching P-Mode. This means that when multiple P-Modes with the highest match score are found none 
     * is returned. 
     *
     * @param mu        The user message message unit to find the P-Mode for
     * @return          The P-Mode for the message unit if the message unit can be matched to a <b>single</b> P-Mode,
     *                  <code>null</code> if no P-Mode could be found for the user message message unit.
     */
    public static IPMode forReceivedUserMessage(final IUserMessage mu, final Logger log) {
			  System.out.println("Find p mode for received user message.");
        final IPModeSet pmodes = HolodeckB2BCoreInterface.getPModeSet();

				if (pmodes == null){
            System.out.println("No p modes found return null");
            log.error("No p modes found return null");
            return null;
        } else {
					  System.out.println("pmode set pmodes is not null.");
					  log.info("pmode set pmodes is not null.");
				}

        IPMode    hPMode = null;
        int       hValue = 0;
        boolean   multiple = false;
        
        
        for (final IPMode p : pmodes.getAll()) {
          System.out.println("Check for p mode: " + p.getId());
          log.info("Check for p mode: ", p.getId());
        	// If the P-Mode MEP binding does not start with the ebMS3 namespace URI it does not apply to ebMS3/AS4 and
        	// therefore should be ignored
        	if (!p.getMepBinding().startsWith(EbMSConstants.EBMS3_NS_URI)){
            System.out.println("Next p mode because MEP binding does not start with EBMS3_NS_URI it was: " + p.getMepBinding());
            log.info("Next p mode because MEP binding does not start with EBMS3_NS_URI it was:", p.getMepBinding());
        		continue;
					} else {
						System.out.println("mep binding starts with EBMS3_NS_URI.");
						log.info("mep binding starts with EBMS3_NS_URI.");
					}
        	
        	/*
        	 * First step is to determine if the P-Mode should be evaluated, i.e. if it governs message receiving. For
        	 * a 2-Way P-Mode this is always true. But for 1-Way P-Modes this is only the case when it is not triggering
        	 * a Push or responding to a Pull.  
        	 */
        	final boolean initiator = PModeUtils.isHolodeckB2BInitiator(p);
          System.out.println("p mode initiator : " + initiator);
          log.info("p mode initiator : ", initiator);
        	final String  mepBinding = p.getMepBinding();
          System.out.println("p mode mep binding : " + mepBinding);
          log.info("p mode mep binding : ", mepBinding);

        	if ((initiator && mepBinding.equals(EbMSConstants.ONE_WAY_PUSH)) // sending using Push
    		|| (!initiator && mepBinding.equals(EbMSConstants.ONE_WAY_PULL))) // sending using Pull
					{
						System.out.println("Next p mode because sending using Push or sending using pull");
						log.info("Next p mode because sending using Push or sending using pull");
                continue;            
					} else {
						System.out.println("Check further initiator and mep binding match for rec user message.");
						log.info("Check further initiator and mep binding match for rec user message.");
					}

        	/*
        	 * Now first check the generic meta-data elements like P-Mode identifier, agreement reference and trading
        	 * partners.
        	 */        	
            int cValue = 0;
						System.out.println("cValue : " + cValue);
						log.info("cValue : ", cValue);
            // P-Mode id and agreement info are contained in optional element
            final IAgreementReference agreementRef = mu.getCollaborationInfo().getAgreement();

						System.out.println("Check include id");
						log.info("Check include id");
            if (p.includeId() != null && p.includeId()) {
                // The P-Mode id can be used for matching, so check if one is given in message
                System.out.println("p mode uses incldeId");
                log.info("p mode uses incldeId");
                if (agreementRef != null) {
                    final String pid = agreementRef.getPModeId();
                    System.out.println("agreement - p mode id : "+ pid);
                    log.info("agreement - p mode id : ", pid);
                    if (!Utils.isNullOrEmpty(pid) && pid.equals(p.getId())){
											  System.out.println("Augment cValue : " + cValue + " because p mode id matches.");
											  log.info("Augment cValue : " + cValue + " because p mode id matches.");
                        cValue = MATCH_WEIGHTS.get(PARAMETERS.ID);
												System.out.println("cValue : " + cValue);
												log.info("cValue : ", cValue);
										} else {
											  System.out.println("pid is null or pid does not equal p.getId()");
											  log.info("pid is null or pid does not equal p.getId()");
										}
                } else {
									System.out.println("agreementRef was null");
									log.info("agreementRef was null");
								}
            } else {
							System.out.println("includeId was null or includeId evaluates to false.");
							log.info("includeId was null or includeId evaluates to false.");
						}

            // Check agreement info
						System.out.println("Check agreement info");
						log.info("Check agreement info");
            final IAgreement agreementPMode = p.getAgreement();
            if (agreementPMode != null) {
							  System.out.println("agreementPMode is not null");
							  log.info("agreementPMode is not null");

								if ( agreementRef == null ) {
									System.out.println("agreementRef is null.");
									log.info("agreementRef is null.");
								} else {
									System.out.println("agreementRef name : " + agreementRef.getName());
									log.info("agreementRef name : ", agreementRef.getName());
								}

								System.out.println("agreementPmode name : " + agreementPMode.getName());
								log.info("agreementPmode name : ", agreementPMode.getName());

                final int i = Utils.compareStrings(agreementRef != null ? agreementRef.getName() : null
                                                  , agreementPMode.getName());
								System.out.println("switch_i : " + i);
								log.info("switch_i : ", i);
                switch (i) {
                    case -2 :
                    case 2 :
											  System.out.println("Next p mode - mismatch on agreement name...");
											  log.info("Next p mode - mismatch on agreement name...");
                        // mismatch on agreement name, either because different or one defined in P-Mode but not in msg
                        continue;
                    case 0 :
                        // names equal, but for match also types must be equal
                        final int j = Utils.compareStrings(agreementRef.getType(), agreementPMode.getType());
											  System.out.println("agreementRef type : " + agreementRef.getType());
											  log.info("agreementRef type : " + agreementRef.getType());
											  System.out.println("agreementPMode type : " + agreementPMode.getType());
											  log.info("agreementPMode type : ", agreementPMode.getType());

												System.out.println("switch_j : " + j);
												log.info("switch_j : " + j);

                        if (j == -1 || j == 0){
												  	System.out.println("Augment cValue : " + cValue + " because agreement info matches.");
												  	log.info("Augment cValue : " + cValue + " because agreement info matches.");
                            cValue += MATCH_WEIGHTS.get(PARAMETERS.AGREEMENT);
												    System.out.println("cValue : " + cValue);
												    log.info("cValue : ", cValue);
												}
                        else {
													  System.out.println("Next p mode because of mis-match on agreement type.");
													  log.info("Next p mode because of mis-match on agreement type.");
                            continue; // mis-match on agreement type
												}
                    case -1 :
                        // both P-Mode and message agreement ref are empty, ignore
                    case 1 :
                        // the message contains agreement ref, but P-Mode does not, ignore
                }
            } else {
							System.out.println("agreement p mode is null.");
							log.info("agreement p mode is null.");
						}

            // Check trading partner info
						System.out.println("Check trading partner info");
						log.info("Check trading partner info");
            final ITradingPartner from = mu.getSender(), to = mu.getReceiver();
            ITradingPartner fromPMode = null, toPMode = null;
            /*
             * If HB2B is the initiator of the MEP it will either send the first User Message or Pull Request which 
             * implies that it will receive the User Message from the Responder. If it isn't the initiator the first
             * User Message is either pushed to HB2B by the other MSH or send by HB2B as a response to a Pull Request
             * meaning that the sender is always the Initiator of the MEP.
             */
            if (initiator) {
            	fromPMode = p.getResponder(); toPMode = p.getInitiator();
            } else {
            	fromPMode = p.getInitiator(); toPMode = p.getResponder(); 
            } 

            // Check To info
						System.out.println("Check to to info");
						log.info("Check to to info");
            if (toPMode != null) {
							  System.out.println("to get role : " + to.getRole());
							  log.info("to get role : ", to.getRole());
							  System.out.println("to p mode get role : " + toPMode.getRole());
							  log.info("to p mode get role : ", toPMode.getRole());
                final int c = Utils.compareStrings(to.getRole(), toPMode.getRole());
								System.out.println("compare c : " + c);
								log.info("compare c : ", c);
                if ( c == -1 || c == 0){
									  System.out.println("Augment cValue : " + cValue + " because to info matches.");
									  log.info("Augment cValue : " + cValue + " because to info id matches.");
                    cValue += MATCH_WEIGHTS.get(PARAMETERS.TO_ROLE);
										System.out.println("cValue : " + cValue);
										log.info("cValue : ", cValue);
								}
                else if (c != 1) {
									  System.out.println("Next p mode - mis-match on To party role");
									  log.info("Next p mode - mis-match on To party role");
                    continue; // mis-match on To party role
								}
                Collection<IPartyId> pmodeToIds = toPMode.getPartyIds();
                if (!Utils.isNullOrEmpty(pmodeToIds)) {
                    if (CompareUtils.areEqual(to.getPartyIds(), pmodeToIds)){
									      System.out.println("Augment cValue : " + cValue + " because to ids match.");
									      log.info("Augment cValue : " + cValue + " because to ids match.");
                        cValue += MATCH_WEIGHTS.get(PARAMETERS.TO);
										    System.out.println("cValue : " + cValue);
										    log.info("cValue : ", cValue);
										}
                    else {
											  System.out.println("Next p mode - mis-match on To party id s");
											  log.info("Next p mode - mis-match on To party id s");
                        continue; // mis-match on To party id('s)
										}
								} else {
									System.out.println("pmodeToIds is null or empty");
									log.info("pmodeToIds is null or empty");
								}
            } else {
							System.out.println("to p mode was null");
							log.info("to p mode was null");
						}

            // Check From info
						System.out.println("Check from info");
						log.info("Check from info");
            if (fromPMode != null) {
							  System.out.println("from get role : " + from.getRole());
							  log.info("from get role : ", from.getRole());
							  System.out.println("from p mode get role : " + fromPMode.getRole());
							  log.info("from p mode get role : ", fromPMode.getRole());
                final int c = Utils.compareStrings(from.getRole(), fromPMode.getRole());
								System.out.println("compare c : " + c);
								log.info("compare c : ", c);
                if ( c == -1 || c == 0){
									  System.out.println("Augment cValue : " + cValue + " because to info matches.");
									  log.info("Augment cValue : " + cValue + " because to info id matches.");
                    cValue += MATCH_WEIGHTS.get(PARAMETERS.FROM_ROLE);
										System.out.println("cValue : " + cValue);
										log.info("cValue : ", cValue);
								}
                else if (c != 1) {
									  System.out.println("Next p mode - mis-match on From party role");
									  log.info("Next p mode - mis-match on From party role");
                    continue; // mis-match on From party role
								}
                Collection<IPartyId> pmodeFromIds = fromPMode.getPartyIds();
                if (!Utils.isNullOrEmpty(pmodeFromIds)) {
                    if (CompareUtils.areEqual(from.getPartyIds(), pmodeFromIds)){
									      System.out.println("Augment cValue : " + cValue + " because from ids match.");
									      log.info("Augment cValue : " + cValue + " because from ids match.");
                        cValue += MATCH_WEIGHTS.get(PARAMETERS.FROM);
										    System.out.println("cValue : " + cValue);
										    log.info("cValue : ", cValue);
										} else {
											  System.out.println("Next p mode - mis-match on From party id s");
											  log.info("Next p mode - mis-match on From party id s");
                        continue;  // mis-match on From party id('s)
										}
								} else {
									System.out.println("pmodeFromIds is null or empty");
									log.info("pmodeFromIds is null or empty");
								}
            } else {
						  	System.out.println("from p mode was null");
						  	log.info("from p mode was null");
						}

            /*
             * Remaining meta-data to be matched are defined per Leg basis. All relevant information is contained in the 
             * user message flow, except for the MPC which can also be specified in a pull request flow.
             */ 
            final ILeg leg = PModeUtils.getReceiveLeg(p);
            final IUserMessageFlow  flow = leg.getUserMessageFlow();
            final IBusinessInfo     pmBI = flow != null ? flow.getBusinessInfo() : null;
            if (pmBI != null) {
                // Check Service
								System.out.println("Check service");
								log.info("Check service");
                final IService svcPMode = pmBI.getService();
                if (svcPMode != null) {
                    final IService svc = mu.getCollaborationInfo().getService();
										System.out.println("svc name : " + svc.getName());
										log.info("svc name : " + svc.getName());
										System.out.println("svc p mode name : " + svcPMode.getName());
										log.info("svc p mode name : " + svcPMode.getName());
                    if (svc.getName().equals(svcPMode.getName())) {
											  
											  System.out.println("svc get type : " + svc.getType());
											  log.info("svc get type : " + svc.getType());
												System.out.println("svc p mode get type : " + svcPMode.getType());
												log.info("svc p mode get type : " + svcPMode.getType());
                        final int i = Utils.compareStrings(svc.getType(), svcPMode.getType());

												System.out.println("switch_i : " + i);
												log.info("switch_i : " + i);
                        if (i == -1 || i == 0) {
									          System.out.println("Augment cValue : " + cValue + " because service matches.");
									          log.info("Augment cValue : " + cValue + " because from service matches.");
                            cValue += MATCH_WEIGHTS.get(PARAMETERS.SERVICE);
										        System.out.println("cValue : " + cValue);
										        log.info("cValue : ", cValue);
												}
                        else {
													  System.out.println("Next p mode - mis-match on service type");
													  log.info("Next p mode - mis-match on service type");
                            continue; // mis-match on service type
												}
                    } else {
											  System.out.println("Next p mode - mis-match on service name");
											  log.info("Next p mode - mis-match on service name");
                        continue; // mis-match on service name
										}
                } else {
									System.out.println("svcPMode was null");
									log.info("svcPMode was null");
								}
                // Check Action
								System.out.println("Check action");
								log.info("Check action");

								System.out.println("mu action : " + mu.getCollaborationInfo().getAction());
								log.info("mu action : " + mu.getCollaborationInfo().getAction());
								System.out.println("pmbi action : " + pmBI.getAction());
								log.info("pmbi action : " + pmBI.getAction());
                final int i = Utils.compareStrings(mu.getCollaborationInfo().getAction(), pmBI.getAction());

								System.out.println("compare_i : " + i);
								log.info("compare_i : " + i);
                if (i == 0) {
									  System.out.println("Augment cValue : " + cValue + " because action matches.");
									  log.info("Augment cValue : " + cValue + " because from action matches.");
                    cValue += MATCH_WEIGHTS.get(PARAMETERS.ACTION);
										System.out.println("cValue : " + cValue);
										log.info("cValue : ", cValue);
								}
                else if (i == -2) {
									  System.out.println("Next p mode - mis-match on action");
									  log.info("Next p mode - mis-match on action");
                    continue; // mis-match on action
								}
            } else {
								System.out.println("pmBI was null");
								log.info("pmBI was null");
						}

            /*
             * Check MPC, first check the MPC defined in the User Message flow, and if there is none there, check
             * if there is maybe on in Pull Request flow. When no MPC is provided the default MPC is used (applies to
             * both message and P-Mode)
             */            
            String mpc = mu.getMPC();
						System.out.println("check mpc");
						log.info("check mpc");

						System.out.println("mu mpc : " + mpc);
						log.info("mu mpc : " + mpc);

            if (Utils.isNullOrEmpty(mpc)) {
							  System.out.println("mu mpc was null or empty use default mpc");
							  log.info("mu mpc was null or empty use default mpc");
                mpc = EbMSConstants.DEFAULT_MPC;
						} else {
							  System.out.println("mu mpc is null or empty");
							  log.info("mu mpc is null or empty");
						}

						if ( pmBI == null ) {
							  System.out.println("pmBI was null");
							  log.info("pmBI was null");
						} else {
							  System.out.println("pmbi mpc : " + pmBI.getMpc());
							  log.info("pmbi mpc : " + pmBI.getMpc());
						}
            String mpcPMode = pmBI != null ? pmBI.getMpc() : null;
            
            if (Utils.isNullOrEmpty(mpcPMode) && !Utils.isNullOrEmpty(leg.getPullRequestFlows())) {
							System.out.println("mpcPmode null or empty and leg pull request flow is not null or empty");
							log.info("mpcPmode null or empty and leg pull request flow is not null or empty");
            	mpcPMode = leg.getPullRequestFlows().iterator().next().getMPC();        
                if (Utils.isNullOrEmpty(mpcPMode)){
									  System.out.println("p mode mpc is null or empty. Use default mpc.");
									  log.info("p mode mpc is null or empty. Use default mpc.");
                    mpcPMode = EbMSConstants.DEFAULT_MPC;
								}
								System.out.println("mpc p mode : " + mpcPMode);
								log.info("mpc p mode : " + mpcPMode);
                // Now compare MPC, but take into account that MPC in a PullRequestFlow can be a sub MPC, so the one
                // from the message can be a parent MPC
                if (mpcPMode.startsWith(mpc)) {
									  System.out.println("Augment cValue : " + cValue + " because mpc matches.");
									  log.info("Augment cValue : " + cValue + " because from mpc matches.");
                    cValue += MATCH_WEIGHTS.get(PARAMETERS.MPC);
										System.out.println("cValue : " + cValue);
										log.info("cValue : ", cValue);
								}
                else {
									  System.out.println("Next p mode - mis-match on mpc");
									  log.info("Next p mode - mis-match on mpc");
                    continue; // mis-match on MPC
								}
            } else {
							  System.out.println("not : mpcPmode null or empty and leg pull request flow is not null or empty");
							  log.info("not : mpcPmode null or empty and leg pull request flow is not null or empty");
                // If no MPC is given in P-Mode, it uses the default
                if (Utils.isNullOrEmpty(mpcPMode)) {
									  System.out.println("mpcPMode is null or empty. Use default mpc for p mode");
									  log.info("mpcPMode is null or empty. Use default mpc for p mode");
                    mpcPMode = EbMSConstants.DEFAULT_MPC;
								}

								System.out.println("p mode mpc : " + mpcPMode);
								log.info("p mode mpc : " + mpcPMode);
                // Now compare the MPC values
                if (mpc.equals(mpcPMode)) {
									  System.out.println("Augment cValue : " + cValue + " because mpc matches 2.");
									  log.info("Augment cValue : " + cValue + " because from mpc matches 2.");
                    cValue += MATCH_WEIGHTS.get(PARAMETERS.MPC);
										System.out.println("cValue : " + cValue);
										log.info("cValue : ", cValue);
								}
                else {
									  System.out.println("Next p mode - mis-match on MPC");
									  log.info("Next p mode - mis-match on MPC");
                    continue; // mis-match on MPC
								}
            }
            
            /*
             * Check the message properties. Only the properties defined in the P-Mode are checked for matching, i.e.
             * when a property exists in the message, but is not defined in the P-Mode, it is ignored. Properties 
             * defined in the P-Mode, but not available in the message result in a mismatch.    
             */
						System.out.println("Check properties");
						log.info("Check properties");
            Collection<IProperty> pModeProperties = pmBI != null ? pmBI.getProperties() : null;
            if (!Utils.isNullOrEmpty(pModeProperties)) { 
            	Collection<IProperty> messageProperties = mu.getMessageProperties();
            	if (Utils.isNullOrEmpty(messageProperties)){ 
								System.out.println("Next p mode - mis-match because properties defined in P-Mode are missing");
								log.info("Next p mode - mis-match because properties defined in P-Mode are missing");
            		continue; // mismatch because properties defined in P-Mode are missing
							} else {
								System.out.println("messageProperties is not null or empty");
								log.info("messageProperties is not null or empty");
							}
            	boolean propMisMatch = false;
            	for(IProperty pp : pModeProperties) {
								System.out.println("compare properties for p mode property : ((" + pp.getName() + " :: " + pp.getType() + " :: " + pp.getValue() + "))");
								log.info("compare properties for p mode property : ((" + pp.getName() + " :: " + pp.getType() + " :: " + pp.getValue() + "))");
            		if (messageProperties.stream().anyMatch(mp -> CompareUtils.areEqual(mp, pp))) {
									System.out.println("Augment cValue : " + cValue + " because msg property matches.");
									log.info("Augment cValue : " + cValue + " because msg property matches.");
            			cValue += MATCH_WEIGHTS.get(PARAMETERS.MSG_PROPERTY);
									System.out.println("cValue : " + cValue);
									log.info("cValue : ", cValue);
								}
            		else {
									System.out.println("Set propMisMatch true");
									log.info("Set propMisMatch true");
            			propMisMatch = true;
								}
            	}
            	if (propMisMatch) {
								System.out.println("Next p mode - mismatch on a property");
								log.info("Next p mode - mismatch on a property");
            		continue; // mismatch on a property
							}
            } else {
							  System.out.println("pModeProperties are null or empty");
							  log.info("pModeProperties are null or empty");
						}
            
            // Does this P-Mode better match to the message meta data than the current highest match?
						System.out.println("Compare current score with high score.");
						log.info("Compare current score with high score.");

            System.out.println("Check if this p mode is the best match.");
            log.info("Check if this p mode is the best match.");
            System.out.println("hValue : " + hValue);
            log.info("hValue : ", hValue);
            System.out.println("cValue : " + cValue);
            log.info("cValue : ", cValue);

            if (cValue > hValue) {
                // Yes, it does, set it as new best match
							  System.out.println("Set this p mode as new best match.");
							  log.info("Set this p mode as new best match.");
                hValue = cValue;
                hPMode = p;
                multiple = false;
            } else if (cValue == hValue) {
							  System.out.println("This p mode maches equally well as the current high score");
							  log.info("This p mode maches equally well as the current high score");
                // It has the same match as the current highest scoring one
                multiple = true;
						}
        }

        // Only return a single P-Mode
        System.out.println("multiple : " + multiple);
        log.info("multiple : ", multiple);

        if ( hPMode == null ) {
            System.out.println("hPMode is null.");
            log.info("hPMode is null.");
        } else {
            System.out.println("hPMode : " + hPMode.getId());
            log.info("hPMode : ", hPMode.getId());
        }

        return !multiple ? hPMode : null;
    }

    /**
     * Gets the list of P-Modes for which Holodeck B2B is the responder in a pull operation for the given MPC and
     * authentication info which can consist of the signature and the username tokens in the security header targeted to
     * the <i>default</i> and <i>ebms</i> role/actor.
     *
     * @param authInfo  The authentication info included in the message.
     * @param mpc       The <i>MPC</i> that the message are exchanged on
     * @return          Collection of P-Modes for which Holodeck B2B is the responder in a pull operation for the given
     *                  MPC and authentication info
     * @throws SecurityProcessingException
     */
    public static Collection<IPMode> findForPulling(final Collection<ISecurityProcessingResult> authInfo,
                                                    final String mpc) throws SecurityProcessingException {
        final ArrayList<IPMode> pmodesForPulling = new ArrayList<>();

        for(final IPMode p : HolodeckB2BCoreInterface.getPModeSet().getAll()) {
            // Check if this P-Mode uses pulling with Holodeck B2B being the responder
            final ILeg leg = PModeUtils.getInPullRequestLeg(p);
            if (leg != null) {
                boolean authorized = false;
                // Get the security configuration of the trading partner
                ISecurityConfiguration tpSecCfg = null;
                if (PModeUtils.isHolodeckB2BInitiator(p) && p.getResponder() != null)
                    tpSecCfg = p.getResponder().getSecurityConfiguration();
                else if (!PModeUtils.isHolodeckB2BInitiator(p) && p.getInitiator() != null)
                    tpSecCfg = p.getInitiator().getSecurityConfiguration();

                // Security config can also be defined per sub-channel in a PullRequestFlow, so these must be checked
                // as well
                final Collection<IPullRequestFlow> flows = leg.getPullRequestFlows();
                if (Utils.isNullOrEmpty(flows)) {
                    // There is no specific configuration for pulling, so use trading partner security settings only
                    // also means we need to check the MPC on leg level
                    authorized = checkMainMPC(leg, mpc) && verifyPullRequestAuthorization(null, tpSecCfg, authInfo);
                } else {
                    for (final Iterator<IPullRequestFlow> it = flows.iterator(); it.hasNext() && !authorized;) {
                        final IPullRequestFlow flow = it.next();
                        // Check if mpc matches to this specific PR-flow
                        authorized = checkSubMPC(flow, mpc)
                                     && verifyPullRequestAuthorization(flow.getSecurityConfiguration(),
                                                                        tpSecCfg,
                                                                        authInfo);
                    }
                }
                // If the info from the message is succesfully verified this P-Mode can be pulled
                if (authorized)
                    pmodesForPulling.add(p);
            }
        }

        return pmodesForPulling;
    }

    /**
     * Checks if the given MPC is equal to or a sub-channel of the MPC on which user messages are exchanged for the
     * given Leg.
     *
     * @param leg   The Leg
     * @param mpc   The mpc that must be checked
     * @return      <code>true</code> if the given MPC starts with or is equal to the one defined in the Leg, taking
     *              into account that a <code>null</code> value is equal to the default MPC, or if no MPC is specified
     *              on the leg,<br>
     *              <code>false</code> otherwise
     */
    private static boolean checkMainMPC(final ILeg leg, final String mpc) {
        String pModeMPC = null;
        try {
            pModeMPC = leg.getUserMessageFlow().getBusinessInfo().getMpc();
        } catch (final NullPointerException npe) {
            pModeMPC = null;
        }

        return ((Utils.isNullOrEmpty(pModeMPC) || EbMSConstants.DEFAULT_MPC.equalsIgnoreCase(pModeMPC))
                && ((Utils.isNullOrEmpty(mpc)) || EbMSConstants.DEFAULT_MPC.equalsIgnoreCase(mpc))
               )
               || (!Utils.isNullOrEmpty(pModeMPC) && !Utils.isNullOrEmpty(mpc)
                     && mpc.toLowerCase().startsWith(pModeMPC.toLowerCase()));
    }

    /**
     * Checks if the given MPC is equal to the sub channel MPC defined in the given [pull request] flow.
     *
     * @param flow  The pull request flow to check
     * @param mpc   The mpc that must be checked
     * @return      <code>true</code> if
     *                  an MPC is defined in the pull request flow and it matches the given MPC,<br>
     *                  or when no MPC is defined for the pull request flow,<br>
     *              <code>false</code> otherwise
     */
    private static boolean checkSubMPC(final IPullRequestFlow flow, final String mpc) {
        String pModeMPC = null;
        try {
            pModeMPC = flow.getMPC();
        } catch (final NullPointerException npe) {
            pModeMPC = null;
        }

        return ((Utils.isNullOrEmpty(pModeMPC) || EbMSConstants.DEFAULT_MPC.equalsIgnoreCase(pModeMPC))
                && ((Utils.isNullOrEmpty(mpc)) || EbMSConstants.DEFAULT_MPC.equalsIgnoreCase(mpc))
               )
               || (!Utils.isNullOrEmpty(mpc) && mpc.equalsIgnoreCase(pModeMPC));
    }

    /**
     * Helper method to verify that the required authorization defined for the Pull Request is correctly satisfied.
     * <p>As described in the ebMS V3 Core Specification there are four option to include the authentication information
     * for a Pull Request, that is using a:<ol>
     * <li>Digital signature in the default WSS Header,</li>
     * <li>Username token in the default WSS header,</li>
     * <li>Username token in the WSS header addressed to the "ebms" actor/role,</li>
     * <li>Transfer-protocol-level identity-authentication mechanism (e.g. TLS)</li></ol>
     * Holodeck B2B supports the first three options, either on their own or as a combination. By default these settings
     * are defined on the trading partner level. But to support authentication for multiple sub-channels or only for
     * the Pull Request it is possible to define the settings on the <i>pull request flow</i>. When settings are
     * provided both at the trading partner and pull request flow the latter take precedence and will be used for the
     * verification of the supplied authentication info.
     * <p>NOTE: The pull request flow specific configuration only allows for authentication options 1 (signature in
     * default header) and 3 (username token in "ebms" header).
     *
     * @param pullSecCfg    The {@link ISecurityConfiguration} specified on the pull request flow that applies to this
     *                      <i>PullRequest</i>
     * @param tpSecCfg      The {@link ISecurityConfiguration} specified for the trading partner that is the sender of
     *                      the <i>PullRequest</i>
     * @param authInfo      All authentication info provided in the received message. 
     * @return              <code>true</code> if the received message satisfies the authentication requirements defined
     *                      in the flow, <br>
     *                      <code>false</code> otherwise.
     */
    private static boolean verifyPullRequestAuthorization(final ISecurityConfiguration pullSecCfg,
                                                          final ISecurityConfiguration tpSecCfg,
                                                          final Collection<ISecurityProcessingResult> authInfo)
                                                                                    throws SecurityProcessingException {
        boolean verified = true;

        // If there are no security parameters specified there is no authentication expected, so there should be no
        // authentication info in the message
        if (pullSecCfg == null && tpSecCfg == null)
            return Utils.isNullOrEmpty(authInfo);
        else if (Utils.isNullOrEmpty(authInfo))
            return false;

        // Verify username token in ebms header, first check if pull request flow contains config for this UT
        IUsernameTokenConfiguration expectedUT = pullSecCfg == null ? null : pullSecCfg.getUsernameTokenConfiguration(
                                                                                             SecurityHeaderTarget.EBMS);
        if (expectedUT == null)
            // if not fall back to trading partner config
            expectedUT = tpSecCfg == null ? null : tpSecCfg.getUsernameTokenConfiguration(SecurityHeaderTarget.EBMS);

        Optional<ISecurityProcessingResult> secToken = authInfo.parallelStream()
        												  .filter(ai -> ai instanceof IUsernameTokenProcessingResult 
        													   	 && ai.getTargetedRole() == SecurityHeaderTarget.EBMS)
        												  .findFirst();
        
        verified = VerificationUtils.verifyUsernameToken(expectedUT, 
        								 secToken.isPresent() ? (IUsernameTokenProcessingResult) secToken.get() : null);

        // Verify user name token in default header
        expectedUT = tpSecCfg == null ? null :
                                tpSecCfg.getUsernameTokenConfiguration(SecurityHeaderTarget.DEFAULT);
        secToken = authInfo.parallelStream().filter(ai -> ai instanceof IUsernameTokenProcessingResult 
				   	 									&& ai.getTargetedRole() == SecurityHeaderTarget.DEFAULT)
				  						    .findFirst();
        verified &= VerificationUtils.verifyUsernameToken(expectedUT,
        								 secToken.isPresent() ? (IUsernameTokenProcessingResult) secToken.get() : null);
        
        // Verify that the expected certificate was used for creating the signature, again start with configuration from
        // PR-flow and fall back to TP
        ISigningConfiguration expectedSig = pullSecCfg == null ? null : pullSecCfg.getSignatureConfiguration();
        if (expectedSig == null)
            expectedSig = tpSecCfg == null ? null : tpSecCfg.getSignatureConfiguration();

        secToken = authInfo.parallelStream().filter(ai -> ai instanceof ISignatureProcessingResult 
													   && ai.getTargetedRole() == SecurityHeaderTarget.DEFAULT)
        									.findFirst();
        verified &= VerificationUtils.verifySigningCertificate(expectedSig,
        									secToken.isPresent() ? (ISignatureProcessingResult) secToken.get() : null);

        return verified;
    }

    /**
     * Retrieves all P-Modes in the current P-Mode set which specify the given URL as the destination of <i>Error</i>
     * signals, i.e. <code>PMode[1].ErrorHandling.ReceiverErrorsTo</code> = <i>«specified URL»</i> or when no specific
     * URL is specified for errors <code>PMode[1].Protocol.Address</code> = <i>«specified URL»</i>
     *
     * @param url   The destination URL
     * @return      Collection of {@link IPMode}s for which errors must be sent to the given URL. When no such P-Mode
     *              exists <code>null</code> is returned
     */
    public static Collection<IPMode> getPModesWithErrorsTo(final String url) {
        final Collection<IPMode>  result = new ArrayList<>();

        for(final IPMode p : HolodeckB2BCoreInterface.getPModeSet().getAll()) {
            // Get all relevent P-Mode info
            final ILeg leg = p.getLegs().iterator().next();
            final IProtocol protocolInfo = leg.getProtocol();
            final IUserMessageFlow flow = leg.getUserMessageFlow();
            final IErrorHandling errorHandling = flow != null ? flow.getErrorHandlingConfiguration() : null;
            // First check if error has specific URL defined or if generic address should be used
            if (errorHandling != null && url.equalsIgnoreCase(errorHandling.getReceiverErrorsTo()))
                result.add(p);
            else if (protocolInfo != null && url.equalsIgnoreCase(protocolInfo.getAddress()))
                result.add(p);
        }

        return result;
    }

    /**
     * Retrieves all P-Modes in the current P-Mode set which specify the given URL as the destination of <i>Receipt</i>
     * signals, i.e. <code>PMode[1].Security.SendReceipt.ReplyTo</code> = <i>«specified URL»</i> or when no specific
     * URL is specified for errors <code>PMode[1].Protocol.Address</code> = <i>«specified URL»</i>
     * <p>NOTE: This P-Mode parameter is not defined in the ebMS V3 Core Specification but defined in Part 2 (see issue
     * https://tools.oasis-open.org/issues/browse/EBXMLMSG-33?jql=project%20%3D%20EBXMLMSG).
     *
     * @param url   The destination URL
     * @return      Collection of {@link IPMode}s for which receipts must be sent to the given URL. When no such P-Mode
     *              exists <code>null</code> is returned
     */
    public static Collection<IPMode> getPModesWithReceiptsTo(final String url) {
        final Collection<IPMode>  result = new ArrayList<>();

        for(final IPMode p : HolodeckB2BCoreInterface.getPModeSet().getAll()) {
            // Get all relevent P-Mode info
            final ILeg leg = p.getLegs().iterator().next();
            final IProtocol protocolInfo = leg.getProtocol();
            final IReceiptConfiguration rcptConfig = leg.getReceiptConfiguration();
            if (rcptConfig != null && url.equalsIgnoreCase(rcptConfig.getTo()))
                result.add(p);
            else if (protocolInfo != null && url.equalsIgnoreCase(protocolInfo.getAddress()))
                result.add(p);
        }

        return result;
    }

}
