package org.batfish.datamodel;

import org.batfish.common.util.ComparableStructure;

import com.fasterxml.jackson.annotation.JsonIdentityReference;
import com.fasterxml.jackson.annotation.JsonPropertyDescription;

public class IkeGateway extends ComparableStructure<String> {

   /**
    *
    */
   private static final long serialVersionUID = 1L;

   private Ip _address;

   private Interface _externalInterface;

   private IkePolicy _ikePolicy;

   private Ip _localAddress;

   private String _localId;

   private String _remoteId;

   public IkeGateway(String name) {
      super(name);
   }

   @Override
   public boolean equals(Object obj) {
      if (this == obj) {
         return true;
      }
      IkeGateway other = (IkeGateway) obj;
      if (!other._address.equals(_address)) {
         return false;
      }
      if (!other._externalInterface.equals(_externalInterface)) {
         return false;
      }
      if (!other._ikePolicy.equals(_ikePolicy)) {
         return false;
      }
      if (!other._localAddress.equals(_localAddress)) {
         return false;
      }
      if (!other._localId.equals(_localId)) {
         return false;
      }
      if (!other._remoteId.equals(_remoteId)) {
         return false;
      }
      return true;
   }

   @JsonPropertyDescription("Remote IP address of IKE gateway")
   public Ip getAddress() {
      return _address;
   }

   @JsonPropertyDescription("Logical (non-VPN) interface from which to connect to IKE gateway. This interface is used to determine source-address for the connection.")
   public Interface getExternalInterface() {
      return _externalInterface;
   }

   @JsonIdentityReference(alwaysAsId = true)
   @JsonPropertyDescription("IKE policy to be used with this IKE gateway. Stored as @id.")
   public IkePolicy getIkePolicy() {
      return _ikePolicy;
   }

   @JsonPropertyDescription("Local IP address from which to connect to IKE gateway. Used instead of external interface.")
   public Ip getLocalAddress() {
      return _localAddress;
   }

   @JsonPropertyDescription("Local IKE ID used in connection to IKE gateway.")
   public String getLocalId() {
      return _localId;
   }

   @JsonPropertyDescription("Remote IKE ID of IKE gateway.")
   public String getRemoteId() {
      return _remoteId;
   }

   public void setAddress(Ip address) {
      _address = address;
   }

   public void setExternalInterface(Interface externalInterface) {
      _externalInterface = externalInterface;
   }

   public void setIkePolicy(IkePolicy ikePolicy) {
      _ikePolicy = ikePolicy;
   }

   public void setLocalAddress(Ip localAddress) {
      _localAddress = localAddress;
   }

   public void setLocalId(String localId) {
      _localId = localId;
   }

   public void setRemoteId(String remoteId) {
      _remoteId = remoteId;
   }

}
