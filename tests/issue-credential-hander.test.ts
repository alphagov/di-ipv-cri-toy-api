import { injectLambdaContext, Logger } from "@aws-lambda-powertools/logger";
import { Metrics } from "@aws-lambda-powertools/metrics";
import errorMiddleware from "../lambdas/middlewares/error/error-middleware";
import validateHeaderBearerTokenMiddleware from "../lambdas/middlewares/validate-header-bearer-token-middleware";
import getSessionByAccessTokenMiddleware from "../lambdas/middlewares/session/get-session-by-access-token-middleware";
import middy from "@middy/core";
import { IssueCredentialLambda } from "../lambdas/issue-credential/src/issue-credential-handler";
import setGovUkSigningJourneyIdMiddleware from "../lambdas/middlewares/session/set-gov-uk-signing-journey-id-middleware";
import getToyByIdMiddleware from "../lambdas/middlewares/toy/get-toy-by-session-id-middleware";
import { ConfigService } from "../lambdas/common/config/config-service";
import { APIGatewayProxyEvent, Context } from "aws-lambda";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import initialiseConfigMiddleware from "../lambdas/middlewares/config/initialise-config-middleware";
import { CommonConfigKey } from "../lambdas/types/config-keys";
import {
  GetParameterCommand,
  ParameterType,
  SSMClient,
} from "@aws-sdk/client-ssm";
import { AuditService } from "../lambdas/common/services/audit-service";
import {
  AuditEventContext,
  AuditEventType,
} from "../lambdas/types/audit-event";
import getSessionByIdMiddleware from "../lambdas/middlewares/session/get-session-by-id-middleware";
import { SessionService } from "../lambdas/services/session-service";
import { JwtSigner } from "../lambdas/jwt-signer/jwt-signer";
jest.mock("@aws-sdk/client-ssm", () => ({
  __esModule: true,
  ...jest.requireActual("@aws-sdk/client-ssm"),
  GetParameterCommand: jest.fn(),
}));
jest.mock("@aws-sdk/lib-dynamodb", () => ({
  __esModule: true,
  ...jest.requireActual("@aws-sdk/lib-dynamodb"),
  GetCommand: jest.fn(),
  QueryCommandInput: jest.fn(),
}));
describe("issue-credential-handler.ts", () => {
  const getParameterCommand = jest.mocked(GetParameterCommand);
  let logger: jest.MockedObjectDeep<typeof Logger>;
  let metrics: jest.MockedObjectDeep<typeof Metrics>;
  let dynamoDbClient: jest.MockedObjectDeep<typeof DynamoDBDocument>;
  let mockSSMClient: jest.MockedObjectDeep<typeof SSMClient>;
  let configService: jest.MockedObjectDeep<typeof ConfigService>;
  let auditService: jest.MockedObjectDeep<typeof AuditService>;
  let sessionService: jest.MockedObjectDeep<typeof SessionService>;
  let mockedJwtSigner: jest.MockedObjectDeep<typeof JwtSigner>;
  let lambdaHandler: middy.MiddyfiedHandler;
  let mockEvent: APIGatewayProxyEvent;

  const TOY_CREDENTIAL_ISSUER = "toy_credential_issuer";
  const mockMap = new Map<string, string>();
  const sessionItem = {
    client_id: "toy-cri",
    toy: "marble-race",
    status: "Authenticated",
    sessionId: "6b0f3490-db8b-4803-967d-39d77a2ece21",
    expiryDate: Math.floor(Date.now() / 1000) + 10_000,
    clientIpAddress: "00.00.00",
    subject: "test-subject",
    persistentSessionId: "5ef1af56-34cd-4572-87eb-6c1184624eaf",
    clientSessionId: "7c852b9d-4c9a-42be-b3cc-c84f87f2cd2b",
  };
  beforeEach(() => {
    process.env = {
      ...process.env,
      AWS_STACK_NAME: "di-ipv-cri-toy-api",
      COMMON_PARAMETER_NAME_PREFIX: "common-cri-api",
    };
    mockMap.set("test-client-id", "test-config-value");
    dynamoDbClient = jest.mocked(DynamoDBDocument);
    mockSSMClient = jest.mocked(SSMClient);
    configService = jest.mocked(ConfigService);
    auditService = jest.mocked(AuditService);
    sessionService = jest.mocked(SessionService);
    mockedJwtSigner = jest.mocked(JwtSigner);

    logger = jest.mocked(Logger);
    metrics = jest.mocked(Metrics);

    const issueCredentialLambda = new IssueCredentialLambda(
      auditService.prototype
    );
    lambdaHandler = middy(
      issueCredentialLambda.handler.bind(issueCredentialLambda)
    )
      .use(
        errorMiddleware(logger.prototype, metrics.prototype, {
          metric_name: TOY_CREDENTIAL_ISSUER,
          message: "Toy lambda error occurred",
        })
      )
      .use(injectLambdaContext(logger.prototype, { clearState: true }))
      .use(
        initialiseConfigMiddleware({
          configService: configService.prototype,
          config_keys: [CommonConfigKey.SESSION_TABLE_NAME],
        })
      )
      .use(validateHeaderBearerTokenMiddleware())
      .use(
        getSessionByAccessTokenMiddleware({
          configService: configService.prototype,
          dynamoDbClient: dynamoDbClient.prototype,
        })
      )
      .use(
        getToyByIdMiddleware({
          configService: configService.prototype,
          dynamoDbClient: dynamoDbClient.prototype,
        })
      )
      .use(
        getSessionByIdMiddleware({ sessionService: sessionService.prototype })
      )
      .use(setGovUkSigningJourneyIdMiddleware(logger.prototype));

    jest.spyOn(metrics.prototype, "addMetric").mockImplementation();
    jest.spyOn(logger.prototype, "error").mockImplementation();
    jest
      .spyOn(configService.prototype, "init")
      .mockImplementation((res) => Promise.resolve(res));

    jest
      .spyOn(configService.prototype, "getConfigEntry")
      .mockReturnValue(mockMap);
    jest
      .spyOn(auditService.prototype, "sendAuditEvent")
      .mockReturnValue(Promise.resolve(null));
    jest.spyOn(sessionService.prototype, "getSession").mockReturnValueOnce({});

    const impl = () =>
      jest.fn().mockImplementation(() => Promise.resolve({ Parameters: [] }));

    dynamoDbClient.prototype.query = impl();
    dynamoDbClient.prototype.send = impl();
    mockSSMClient.prototype.send = impl();

    jest.spyOn(configService.prototype, "getParameter").mockReturnValueOnce({
      Value: `/${process.env.AWS_STACK_NAME}/ToyTableName`,
    });
  });

  afterEach(() => jest.resetAllMocks());

  describe("authorization valid, verifiable credential issued", () => {
    beforeEach(() => {
      mockEvent = {
        body: JSON.stringify(sessionItem),
        headers: {
          ["x-forwarded-for"]: "test-client-ip-address",
          ["session-id"]: "6b0f3490-db8b-4803-967d-39d77a2ece21",
          ["authorization"]:
            "Bearer am4Wd9k8fG8sD2a9Bw9E0ov8kSM6K1FkDSUFyA7ZA5o",
        },
      } as unknown as APIGatewayProxyEvent;
      dynamoDbClient.prototype.send.mockImplementationOnce(() =>
        Promise.resolve({ Item: sessionItem })
      );
      dynamoDbClient.prototype.query.mockImplementationOnce(() =>
        Promise.resolve({
          Items: [sessionItem],
        })
      );
      [
        {
          Name: `/${process.env.AWS_STACK_NAME}/MaxJwtTtl`,
          Type: ParameterType.STRING,
          Value: "3",
        },
        {
          Name: `/${process.env.AWS_STACK_NAME}/JwtTtlUnit`,
          Type: ParameterType.STRING,
          Value: "minutes",
        },
        {
          Name: `/${process.env.COMMON_PARAMETER_NAME_PREFIX}/verifiable-credential/issuer`,
          Type: ParameterType.STRING,
          Value: "https://review-toy.dev.account.gov.uk",
        },
        {
          Name: `/${process.env.AWS_STACK_NAME}/release-flags/vc-contains-unique-id`,
          Type: ParameterType.STRING,
          Value: true,
        },
        {
          Name: "/release-flags/vc-expiry-removed",
          Type: ParameterType.STRING,
          Value: true,
        },
      ].forEach((param) => {
        jest
          .spyOn(mockSSMClient.prototype, "send")
          .mockResolvedValueOnce({ Parameter: param });
      });
    });
    it("should return a statuscode of 200", async () => {
      const mockJwt = "mocked.signedjwt.value";
      jest
        .spyOn(mockedJwtSigner.prototype, "createSignedJwt")
        .mockResolvedValueOnce(mockJwt);
      const response = await lambdaHandler(mockEvent, {} as Context);

      expect(getParameterCommand).toBeCalledTimes(5);

      expect(dynamoDbClient.prototype.query).toHaveBeenCalledTimes(1);
      expect(dynamoDbClient.prototype.send).toHaveBeenCalledTimes(1);
      expect(mockSSMClient.prototype.send).toHaveBeenCalledTimes(5);
      expect(response).toEqual({
        statusCode: 200,
        body: mockJwt,
      });
    });

    it("should send audit events", async () => {
      const spy = jest.spyOn(auditService.prototype, "sendAuditEvent");
      const expectedAuditEventContext: AuditEventContext = {
        sessionItem: {
          subject: "test-subject",
          sessionId: "6b0f3490-db8b-4803-967d-39d77a2ece21",
          persistentSessionId: "5ef1af56-34cd-4572-87eb-6c1184624eaf",
          clientSessionId: "7c852b9d-4c9a-42be-b3cc-c84f87f2cd2b",
        },
        clientIpAddress: "00.00.00",
      };
      await lambdaHandler(mockEvent, {} as Context);
      expect(spy).toHaveBeenCalledTimes(2);
      expect(spy).toHaveBeenCalledWith(
        AuditEventType.END,
        expectedAuditEventContext
      );
      expect(spy).toHaveBeenCalledWith(AuditEventType.VC_ISSUED, {
        ...expectedAuditEventContext,
        extensions: {
          toy: "marble-race",
          iss: "https://review-toy.dev.account.gov.uk",
        },
      });
    });
  });
  describe("authorization absent, unable to issue veriable credential", () => {
    beforeEach(() => {
      mockEvent = {
        body: JSON.stringify(sessionItem),
        headers: {
          ["x-forwarded-for"]: "test-client-ip-address",
          ["session-id"]: "6b0f3490-db8b-4803-967d-39d77a2ece21",
          ["authorization"]: "Bearer",
        },
      } as unknown as APIGatewayProxyEvent;
    });
    it("should return a statuscode of 400", async () => {
      const response = await lambdaHandler(mockEvent, {} as Context);

      expect(response.statusCode).toBe(400);
      expect(dynamoDbClient.prototype.query).not.toHaveBeenCalledTimes(1);
      expect(dynamoDbClient.prototype.send).not.toHaveBeenCalledTimes(1);
      expect(mockSSMClient.prototype.send).not.toHaveBeenCalledTimes(4);
    });
  });
});
