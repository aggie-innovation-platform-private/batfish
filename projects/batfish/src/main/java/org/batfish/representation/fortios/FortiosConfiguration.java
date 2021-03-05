package org.batfish.representation.fortios;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import java.util.*;
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
import org.batfish.datamodel.acl.AclLineMatchExpr;
import org.batfish.vendor.VendorConfiguration;

public class FortiosConfiguration extends VendorConfiguration {

  public FortiosConfiguration() {
    _addresses = new HashMap<>();
    _interfaces = new HashMap<>();
    _policies = new LinkedHashMap<>();
    _renameableObjects = new HashMap<>();
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

  /** UUID -> renameable object */
  public @Nonnull Map<BatfishUUID, FortiosRenameableObject> getRenameableObjects() {
    return _renameableObjects;
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
  private final @Nonnull Map<BatfishUUID, FortiosRenameableObject> _renameableObjects;
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
        .forEach(address -> c.getIpSpaces().put(address.getName(), address.toIpSpace(_w)));

    // Convert policies. Must happen after c._ipSpaces is populated
    Map<String, AclLineMatchExpr> convertedServices =
        _services.values().stream()
            .collect(ImmutableMap.toImmutableMap(Service::getName, svc -> svc.toMatchExpr(_w)));
    _policies.values().forEach(policy -> convertPolicy(policy, c, convertedServices));

    // Convert interfaces. Must happen after converting policies
    _interfaces.values().forEach(iface -> convertInterface(iface, c));

    // Count structure references
    markConcreteStructure(FortiosStructureType.ADDRESS);
    markConcreteStructure(FortiosStructureType.SERVICE_CUSTOM);
    markConcreteStructure(FortiosStructureType.INTERFACE);
    return c;
  }

  private void convertPolicy(
      Policy policy, Configuration c, Map<String, AclLineMatchExpr> convertedServices) {
    policy
        .toIpAccessList(c.getIpSpaces(), convertedServices, _w)
        .ifPresent(acl -> c.getIpAccessLists().put(acl.getName(), acl));
  }

  private void convertInterface(Interface iface, Configuration c) {
    String vdom = iface.getVdom();
    assert vdom != null; // An interface with no VDOM set should fail in extraction
    String vrfName = computeVrfName(vdom, iface.getVrfEffective());
    // Referencing a VRF in an interface implicitly creates it
    Vrf vrf = c.getVrfs().computeIfAbsent(vrfName, name -> Vrf.builder().setName(name).build());
    org.batfish.datamodel.Interface.Builder viIface =
        org.batfish.datamodel.Interface.builder()
            .setOwner(c)
            .setName(iface.getName())
            .setVrf(vrf)
            .setDescription(iface.getDescription())
            .setActive(iface.getStatusEffective())
            .setAddress(iface.getIp())
            .setMtu(iface.getMtuEffective())
            .setType(iface.getTypeEffective().toViType());
    // TODO Is this the right VI field for interface alias?
    Optional.ofNullable(iface.getAlias())
        .ifPresent(alias -> viIface.setDeclaredNames(ImmutableList.of(iface.getAlias())));
    viIface.build();
  }

  private @Nullable IpAccessList generateOutgoingFilter(Interface iface, Configuration c) {
    List<IpAccessList> viPolicies =
        _policies.values().stream()
            .filter(policy -> policy.getDstIntf().contains(iface.getName()))
            .map(
                policy ->
                    c.getIpAccessLists()
                        .get(Policy.computeViName(policy.getName(), policy.getNumber())))
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
    lines.add(ExprAclLine.ACCEPT_ALL); // TODO Check default action
    return IpAccessList.builder()
        .setOwner(c)
        .setName(computeOutgoingFilterName(iface.getName()))
        .setLines(lines.build())
        .build();
  }

  private static String computeVrfName(String vdom, int vrf) {
    return String.format("%s:%s", vdom, vrf);
  }

  private static String computeOutgoingFilterName(String iface) {
    return String.format("~%s~outgoing~", iface);
  }
}
