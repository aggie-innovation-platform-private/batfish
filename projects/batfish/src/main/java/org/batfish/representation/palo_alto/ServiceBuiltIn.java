package org.batfish.representation.palo_alto;

import static org.batfish.representation.palo_alto.PaloAltoTraceElementCreators.matchBuiltInServiceTraceElement;
import static org.batfish.representation.palo_alto.PaloAltoTraceElementCreators.matchServiceAnyTraceElement;

import com.google.common.base.Suppliers;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSortedSet;
import java.util.function.Supplier;
import org.batfish.datamodel.HeaderSpace;
import org.batfish.datamodel.IpProtocol;
import org.batfish.datamodel.SubRange;
import org.batfish.datamodel.acl.AclLineMatchExpr;
import org.batfish.datamodel.acl.MatchHeaderSpace;
import org.batfish.datamodel.acl.TrueExpr;

public enum ServiceBuiltIn {
  ANY,
  APPLICATION_DEFAULT,
  SERVICE_HTTP,
  SERVICE_HTTPS;

  private final Supplier<HeaderSpace> _serviceHeaderSpace;

  ServiceBuiltIn() {
    _serviceHeaderSpace = Suppliers.memoize(this::init);
  }

  private HeaderSpace init() {
    switch (this) {
      case SERVICE_HTTP:
        return HeaderSpace.builder()
            .setIpProtocols(ImmutableList.of(IpProtocol.TCP))
            .setDstPorts(ImmutableSortedSet.of(SubRange.singleton(80), new SubRange(8080, 8080)))
            .build();
      case SERVICE_HTTPS:
        return HeaderSpace.builder()
            .setIpProtocols(ImmutableList.of(IpProtocol.TCP))
            .setDstPorts(ImmutableSortedSet.of(SubRange.singleton(443)))
            .build();
        // any and application-default don't match a specific port
      case ANY:
      case APPLICATION_DEFAULT:
      default:
        return null;
    }
  }

  public AclLineMatchExpr toAclLineMatchExpr() {
    switch (this) {
      case ANY:
        return new TrueExpr(matchServiceAnyTraceElement());
      case APPLICATION_DEFAULT:
      case SERVICE_HTTP:
      case SERVICE_HTTPS:
        return new MatchHeaderSpace(
            _serviceHeaderSpace.get(), matchBuiltInServiceTraceElement(getName()));
      default:
        return new MatchHeaderSpace(_serviceHeaderSpace.get());
    }
  }

  public String getName() {
    switch (this) {
      case ANY:
        return "any";
      case APPLICATION_DEFAULT:
        return "application-default";
      case SERVICE_HTTP:
        return "service-http";
      case SERVICE_HTTPS:
        return "service-https";
      default:
        return null;
    }
  }
}
