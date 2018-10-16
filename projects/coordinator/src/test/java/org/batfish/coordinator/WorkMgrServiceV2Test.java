package org.batfish.coordinator;

import static javax.ws.rs.core.Response.Status.FORBIDDEN;
import static javax.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR;
import static javax.ws.rs.core.Response.Status.MOVED_PERMANENTLY;
import static javax.ws.rs.core.Response.Status.OK;
import static javax.ws.rs.core.Response.Status.UNAUTHORIZED;
import static org.glassfish.jersey.client.ClientProperties.FOLLOW_REDIRECTS;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.assertThat;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.GenericType;
import javax.ws.rs.core.Response;
import org.batfish.common.BfConsts;
import org.batfish.common.Container;
import org.batfish.common.CoordConsts;
import org.batfish.common.CoordConstsV2;
import org.batfish.common.Version;
import org.batfish.common.util.CommonUtil;
import org.batfish.coordinator.authorizer.Authorizer;
import org.batfish.datamodel.questions.TestQuestion;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class WorkMgrServiceV2Test extends WorkMgrServiceV2TestBase {
  @Rule public TemporaryFolder _folder = new TemporaryFolder();

  @Before
  public void initContainerEnvironment() throws Exception {
    WorkMgrTestUtils.initWorkManager(_folder);
  }

  private WebTarget getContainersTarget() {
    return target(CoordConsts.SVC_CFG_WORK_MGR2).path(CoordConstsV2.RSC_NETWORKS);
  }

  @Test
  public void getContainers() {
    Response response =
        getContainersTarget()
            .request()
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_VERSION, Version.getVersion())
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_APIKEY, CoordConsts.DEFAULT_API_KEY)
            .get();
    assertThat(response.getStatus(), equalTo(OK.getStatusCode()));
    assertThat(response.readEntity(new GenericType<List<Container>>() {}), empty());

    Main.getWorkMgr().initNetwork("someContainer", null);
    response =
        getContainersTarget()
            .request()
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_VERSION, Version.getVersion())
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_APIKEY, CoordConsts.DEFAULT_API_KEY)
            .get();
    assertThat(response.getStatus(), equalTo(OK.getStatusCode()));
    assertThat(response.readEntity(new GenericType<List<Container>>() {}), hasSize(1));
  }

  @Test
  public void redirectContainer() {
    Response response =
        target(CoordConsts.SVC_CFG_WORK_MGR2)
            .path(CoordConstsV2.RSC_NETWORK)
            .property(FOLLOW_REDIRECTS, false)
            .request()
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_VERSION, Version.getVersion())
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_APIKEY, CoordConsts.DEFAULT_API_KEY)
            .get();
    assertThat(response.getStatus(), equalTo(MOVED_PERMANENTLY.getStatusCode()));
    assertThat(response.getLocation().getPath(), equalTo("/v2/networks"));
  }

  @Test
  public void testGetQuestionTemplatesUnconfigured() {
    Response response =
        target(CoordConsts.SVC_CFG_WORK_MGR2)
            .path(CoordConstsV2.RSC_QUESTION_TEMPLATES)
            .request()
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_VERSION, Version.getVersion())
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_APIKEY, CoordConsts.DEFAULT_API_KEY)
            .get();
    assertThat(response.getStatus(), equalTo(INTERNAL_SERVER_ERROR.getStatusCode()));
  }

  @Test
  public void testGetQuestionTemplatesConfigured() throws Exception {
    String templateName = "template1";
    String templateText = writeTemplateFile(templateName);
    Response response =
        target(CoordConsts.SVC_CFG_WORK_MGR2)
            .path(CoordConstsV2.RSC_QUESTION_TEMPLATES)
            .request()
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_VERSION, Version.getVersion())
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_APIKEY, CoordConsts.DEFAULT_API_KEY)
            .get();

    assertThat(response.getStatus(), equalTo(OK.getStatusCode()));
    assertThat(
        response.readEntity(Map.class), equalTo(ImmutableMap.of(templateName, templateText)));
  }

  private @Nonnull String writeTemplateFile(String templateName) {
    Path questionTemplateDir = _folder.getRoot().toPath().resolve("templates");
    String templateText =
        String.format(
            "{\"class\":\"%s\",\"%s\":{\"%s\":\"%s\"}}",
            TestQuestion.class, BfConsts.PROP_INSTANCE, BfConsts.PROP_INSTANCE_NAME, templateName);
    Path questionTemplateFile = questionTemplateDir.resolve(templateName + ".json");
    questionTemplateDir.toFile().mkdirs();
    CommonUtil.writeFile(questionTemplateFile, templateText);
    Main.getSettings().setQuestionTemplateDirs(ImmutableList.of(questionTemplateDir));
    return templateText;
  }

  @Test
  public void testGetQuestionTemplatesConfiguredVerbose() throws Exception {
    String templateName = "template1";
    String hiddenTemplateName = "__template2";
    String templateText = writeTemplateFile(templateName);
    String hiddenTemplateText = writeTemplateFile(hiddenTemplateName);
    Response response =
        target(CoordConsts.SVC_CFG_WORK_MGR2)
            .path(CoordConstsV2.RSC_QUESTION_TEMPLATES)
            .request()
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_VERSION, Version.getVersion())
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_APIKEY, CoordConsts.DEFAULT_API_KEY)
            .get();

    // when not verbose, hidden template should be absent
    assertThat(response.getStatus(), equalTo(OK.getStatusCode()));
    assertThat(
        response.readEntity(Map.class), equalTo(ImmutableMap.of(templateName, templateText)));

    response =
        target(CoordConsts.SVC_CFG_WORK_MGR2)
            .path(CoordConstsV2.RSC_QUESTION_TEMPLATES)
            .queryParam(CoordConstsV2.QP_VERBOSE, true)
            .request()
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_VERSION, Version.getVersion())
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_APIKEY, CoordConsts.DEFAULT_API_KEY)
            .get();

    // when verbose, hidden template should be present
    assertThat(response.getStatus(), equalTo(OK.getStatusCode()));
    assertThat(
        response.readEntity(Map.class),
        equalTo(
            ImmutableMap.of(templateName, templateText, hiddenTemplateName, hiddenTemplateText)));
  }

  /** Test that the ApiKey is extracted from the correct header */
  @Test
  public void apiKeyValidationAndCorrectReturnCodes() {
    // Set up by making a call to authorize container
    String containerName = "someContainer";
    String otherContainerName = "anotherContainer";
    String myKey = "ApiKey";
    String otherKey = "AnotherApiKey";
    Authorizer auth = new MapAuthorizer();
    Main.setAuthorizer(auth);
    auth.authorizeContainer(myKey, containerName);
    auth.authorizeContainer(otherKey, otherContainerName);
    Main.getWorkMgr().initNetwork(containerName, null);

    // Test that subsequent calls return 200 with correct API key
    Response resp =
        getContainersTarget()
            .path(containerName)
            .request()
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_VERSION, Version.getVersion())
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_APIKEY, myKey)
            .get();
    assertThat(resp.getStatus(), equalTo(OK.getStatusCode()));
    assertThat(
        resp.readEntity(Container.class),
        equalTo(Container.of(containerName, Collections.emptySortedSet())));

    // Test that subsequent calls return 401 unauthorized with unknown API key
    resp =
        getContainersTarget()
            .path(containerName)
            .request()
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_VERSION, Version.getVersion())
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_APIKEY, "unknownKey")
            .get();
    assertThat(resp.getStatus(), equalTo(UNAUTHORIZED.getStatusCode()));
    assertThat(
        resp.readEntity(String.class), equalTo("Authorizer: 'unknownKey' is NOT a valid key"));

    // Test that subsequent calls return 403 forbidden with known API key and no access
    resp =
        getContainersTarget()
            .path(containerName)
            .request()
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_VERSION, Version.getVersion())
            .header(CoordConstsV2.HTTP_HEADER_BATFISH_APIKEY, otherKey)
            .get();
    assertThat(resp.getStatus(), equalTo(FORBIDDEN.getStatusCode()));
    assertThat(
        resp.readEntity(String.class),
        equalTo("network 'someContainer' is not accessible by the api key: AnotherApiKey"));
  }
}
