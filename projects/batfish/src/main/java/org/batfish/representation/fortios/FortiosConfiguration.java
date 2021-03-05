package org.batfish.representation.fortios;

import static org.apache.commons.lang3.ObjectUtils.firstNonNull;

import com.google.common.collect.ImmutableList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.batfish.common.VendorConversionException;
import org.batfish.datamodel.AclAclLine;
import org.batfish.datamodel.AclLine;
import org.batfish.datamodel.Configuration;
import org.batfish.datamodel.ConfigurationFormat;
import org.batfish.datamodel.DeviceModel;
import org.batfish.datamodel.ExprAclLine;
import org.batfish.datamodel.IpAccessList;
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

    // Convert addresses
    _addresses
        .values()
        .forEach(address -> c.getIpSpaces().put(address.getName(), address.toIpSpace()));

    // Convert policies
    _policies.values().forEach(policy -> convertPolicy(policy, c));

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
    IpAccessList outgoingFilter = generateOutgoingFilter(iface, c);
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
        // TODO Check if this should be original flow filter (i.e. if policies act on pre-NAT flows)
        .setOutgoingFilter(outgoingFilter)
        .build();
  }

  private @Nullable IpAccessList generateOutgoingFilter(Interface iface, Configuration c) {
    List<IpAccessList> viPolicies =
        _policies.values().stream()
            .filter(policy -> policy.getDstIntf().contains(iface.getName()))
            .map(policy -> c.getIpAccessLists().get(computePolicyName(policy)))
            .filter(Objects::nonNull)
            .collect(ImmutableList.toImmutableList());
    if (viPolicies.isEmpty()) {
      return null;
    } else if (viPolicies.size() == 1) {
      return viPolicies.get(0);
    }
    ImmutableList.Builder<AclLine> lines = ImmutableList.builder();
    viPolicies.stream()
        .map(IpAccessList::getName)
        .map(policyName -> new AclAclLine("Match policy " + policyName, policyName))
        .forEach(lines::add);
    lines.add(ExprAclLine.REJECT_ALL); // TODO Check default action
    return IpAccessList.builder()
        .setOwner(c)
        .setName(outgoingFilterName(iface.getName()))
        .setLines(lines.build())
        .build();
  }

  private void convertPolicy(Policy policy, Configuration c) {
    if (policy.getStatusEffective() == Policy.Status.DISABLE) {
      // Ignore disabled policy
      return;
    }
    // TODO: Should we incorporate policy.getName() it its name if present?
    // TODO: Might need to generate IpAccessList names per VRF/VDOM
    c.getIpAccessLists().put(computePolicyName(policy), policy.toIpAccessList());
  }

  static String computePolicyName(Policy policy) {
    // TODO: Might need to generate IpAccessList names per VRF/VDOM
    return firstNonNull(policy.getName(), policy.getNumber());
  }

  private static String vrfName(String vdom, int vrf) {
    return String.format("%s:%s", vdom, vrf);
  }

  private static String outgoingFilterName(String iface) {
    return String.format("~%s~outgoing~", iface);
  }
}
