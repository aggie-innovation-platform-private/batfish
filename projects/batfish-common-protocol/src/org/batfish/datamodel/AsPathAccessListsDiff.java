package org.batfish.datamodel;

import java.util.NavigableMap;
import java.util.Set;
import java.util.TreeSet;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class AsPathAccessListsDiff extends ConfigDiffElement {

   protected static final String DIFF_VAR = "diff";
   protected Set<String> _diff;

   @JsonCreator()
   public AsPathAccessListsDiff() {

   }

   public AsPathAccessListsDiff(NavigableMap<String, AsPathAccessList> a,
         NavigableMap<String, AsPathAccessList> b) {
      super(a.keySet(), b.keySet());
      _diff = new TreeSet<>();
      for (String name : super.common()) {
         if (a.get(name).equals(b.get(name))) {
            _identical.add(name);
         }
         else {
            _diff.add(name);
         }
      }
   }

   @JsonProperty(DIFF_VAR)
   public Set<String> getDiff() {
      return _diff;
   }

   public void setDiff(Set<String> diff) {
      _diff = diff;
   }
}
