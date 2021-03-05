package org.batfish.representation.fortios;

import com.google.common.collect.ImmutableList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.batfish.common.VendorConversionException;
import org.batfish.datamodel.Configuration;
import org.batfish.datamodel.ConfigurationFormat;
import org.batfish.datamodel.DeviceModel;
import org.batfish.datamodel.LineAction;
import org.batfish.datamodel.Vrf;
import org.batfish.vendor.VendorConfiguration;

public class FortiosConfiguration extends VendorConfiguration {

  public FortiosConfiguration() {
    _addresses = new HashMap<>();
    _interfaces = new HashMap<>();
    _policies = new LinkedHashMap<>();
    _replacemsgs = new HashMap<>();
    _services = new HashMap<>();
  }

  @Override
  public String getHostname() {
    return _hostname;
  }

  @Override
  public void setHostname(String hostname) {
    _hostname = hostname;
  }

  @Override
  public void setVendor(ConfigurationFormat format) {}

  @Override
  public List<Configuration> toVendorIndependentConfigurations() throws VendorConversionException {
    return ImmutableList.of(toVendorIndependentConfiguration());
  }

  public @Nonnull Map<String, Address> getAddresses() {
    return _addresses;
  }

  public @Nonnull Map<String, Interface> getInterfaces() {
    return _interfaces;
  }

  /** name -> policy */
  public @Nonnull Map<String, Policy> getPolicies() {
    return _policies;
  }

  /** majorType -> minorType -> replacemsg config */
  public @Nonnull Map<String, Map<String, Replacemsg>> getReplacemsgs() {
    return _replacemsgs;
  }

  /** name -> service */
  public @Nonnull Map<String, Service> getServices() {
    return _services;
  }

  private String _hostname;
  private final @Nonnull Map<String, Address> _addresses;
  private final @Nonnull Map<String, Interface> _interfaces;
  // Note: this is a LinkedHashMap to preserve insertion order
  private final @Nonnull Map<String, Policy> _policies;
  private final @Nonnull Map<String, Map<String, Replacemsg>> _replacemsgs;
  private final @Nonnull Map<String, Service> _services;

  private @Nonnull Configuration toVendorIndependentConfiguration() {
    Configuration c = new Configuration(_hostname, ConfigurationFormat.FORTIOS);
    c.setDeviceModel(DeviceModel.FORTIOS_UNSPECIFIED);
    // TODO: verify
    c.setDefaultCrossZoneAction(LineAction.DENY);
    // TODO: verify
    c.setDefaultInboundAction(LineAction.DENY);

    // Convert interfaces
    _interfaces.values().forEach(iface -> convertInterface(iface, c));

    return c;
  }

  private void convertInterface(Interface iface, Configuration c) {
    String vdom = iface.getVdom();
    assert vdom != null; // An interface with no VDOM set should fail in extraction
    String vrfName = vrfName(vdom, iface.getVrfEffective());
    // TODO Does referencing a VRF from an interface implicitly create it?
    Vrf vrf = c.getVrfs().get(vrfName);
    if (vrf == null) {
      vrf = Vrf.builder().setOwner(c).setName(vrfName).build();
    }
    // TODO Handle interface type
    org.batfish.datamodel.Interface.builder()
        .setOwner(c)
        .setName(iface.getName())
        .setVrf(vrf)
        .setDescription(iface.getDescription())
        .setActive(iface.getStatusEffective())
        .setAddress(iface.getIp())
        .setMtu(iface.getMtuEffective())
        .setType(iface.getType().toViType())
        .build();
  }

  private static String vrfName(String vdom, int vrf) {
    return String.format("%s:%s", vdom, vrf);
  }
}
