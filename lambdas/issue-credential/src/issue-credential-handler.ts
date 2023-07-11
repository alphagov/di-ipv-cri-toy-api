import { LambdaInterface } from "@aws-lambda-powertools/commons";
import middy from "@middy/core";
import {
  APIGatewayProxyEvent,
  APIGatewayProxyResult,
  Handler,
} from "aws-lambda";
import { SSMClient } from "@aws-sdk/client-ssm";
import { injectLambdaContext } from "@aws-lambda-powertools/logger";
import errorMiddleware from "../../middlewares/error/error-middleware";
import { AwsClientType, createClient } from "../../common/aws-client-factory";
import { ConfigService } from "../../common/config/config-service";
import { logger, metrics } from "../../common/utils/power-tool";
import validateHeaderBearerTokenMiddleware from "../../middlewares/validate-header-bearer-token-middleware";
import getSessionByAccessTokenMiddleware from "../../middlewares/session/get-session-by-access-token-middleware";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import getToyByIdMiddleware from "../../middlewares/toy/get-toy-by-session-id-middleware";
import setGovUkSigningJourneyIdMiddleware from "../../middlewares/session/set-gov-uk-signing-journey-id-middleware";
import { VerifiableCredentialBuilder } from "../../verifiable-credential/verifiable-credential-builder";
import { VC_CONTEXT } from "../../types/verifiable-credentials";
import { CommonConfigKey } from "../../types/config-keys";
import initialiseConfigMiddleware from "../../middlewares/config/initialise-config-middleware";
import { Subject } from "../../types/subject";
import { ToyItem } from "../../types/toy_item";
import { AuditService } from "../../common/services/audit-service";
import { AuditEventType } from "../../types/audit-event";
import { SQSClient } from "@aws-sdk/client-sqs";
import { SessionItem } from "../../types/session-item";
import { SessionService } from "../../services/session-service";
import { getTimeUnitValue } from "../../common/utils/time-units";
import getSessionByIdMiddleware from "../../middlewares/session/get-session-by-id-middleware";
import { JwtSigner } from "../../jwt-signer/jwt-signer";
import { KMSClient } from "@aws-sdk/client-kms";
const TOY_CREDENTIAL_ISSUER = "toy_credential_issuer";
const dynamoDbClient = createClient(AwsClientType.DYNAMO) as DynamoDBDocument;
const ssmClient = createClient(AwsClientType.SSM) as SSMClient;
const sqsClient = createClient(AwsClientType.SQS) as SQSClient;
const kmsClient = createClient(AwsClientType.SQS) as KMSClient;
const configService = new ConfigService(ssmClient);
const sessionService = new SessionService(dynamoDbClient, configService);
const auditService = new AuditService(
  () => configService.getConfigEntry(CommonConfigKey.VC_ISSUER),
  sqsClient
);
const jwtSigner = new JwtSigner(kmsClient, () =>
  configService.getConfigEntry(CommonConfigKey.VC_KMS_SIGNING_KEY_ID)
);
const builder = new VerifiableCredentialBuilder(ssmClient);
export class IssueCredentialLambda implements LambdaInterface {
  constructor(private readonly auditService: AuditService) {}

  public async handler(
    event: APIGatewayProxyEvent,
    _context: unknown
  ): Promise<APIGatewayProxyResult | { statusCode: number }> {
    logger.info("Toy issue-credential lambda triggered");

    const ttlDuration = (await getMaxJwtTl()).Value;
    const ttlUnit = getTimeUnitValue((await getJwtTlUnit()).Value);
    const toyBody = event.body as unknown as ToyItem;
    const sessionItem = event.body as unknown as SessionItem;

    const vcClaimSet = await builder
      .subject(toyBody.toy)
      .timeToLive(ttlUnit, Number(ttlDuration))
      .verifiableCredentialType("ToyCredential")
      .verifiableCredentialContext([
        VC_CONTEXT.DI_CONTEXT,
        VC_CONTEXT.W3_BASE_CONTEXT,
      ])
      .verifiableCredentialSubject({
        name: [
          {
            nameParts: [
              {
                type: "GivenName",
                value: toyBody.toy.split("-")[0],
              },
              {
                type: "FamilyName",
                value: toyBody.toy.split("-")[1],
              },
            ],
          },
        ],
      } as Subject)
      .build();

    await this.auditService.sendAuditEvent(
      AuditEventType.VC_ISSUED,
      this.auditService.createAuditEventContext(sessionItem, {
        toy: toyBody.toy,
        iss: vcClaimSet.iss,
      })
    );

    await this.auditService.sendAuditEvent(
      AuditEventType.END,
      this.auditService.createAuditEventContext(sessionItem)
    );

    return {
      statusCode: 200,
      body: await jwtSigner.createSignedJwt(vcClaimSet),
    };
  }
}
const getJwtTlUnit = async () =>
  await configService.getParameter(`/${process.env.AWS_STACK_NAME}/JwtTtlUnit`);
const getMaxJwtTl = async () =>
  await configService.getParameter(`/${process.env.AWS_STACK_NAME}/MaxJwtTtl`);
const handlerClass = new IssueCredentialLambda(auditService);
export const lambdaHandler: Handler = middy(
  handlerClass.handler.bind(handlerClass)
)
  .use(
    errorMiddleware(logger, metrics, {
      metric_name: TOY_CREDENTIAL_ISSUER,
      message: "Toy lambda error occurred",
    })
  )
  .use(injectLambdaContext(logger, { clearState: true }))
  .use(
    initialiseConfigMiddleware({
      configService: configService,
      config_keys: [
        CommonConfigKey.SESSION_TABLE_NAME,
        CommonConfigKey.VC_ISSUER,
        CommonConfigKey.VC_KMS_SIGNING_KEY_ID,
      ],
    })
  )
  .use(validateHeaderBearerTokenMiddleware())
  .use(
    getSessionByAccessTokenMiddleware({
      configService: configService,
      dynamoDbClient: dynamoDbClient,
    })
  )
  .use(
    getToyByIdMiddleware({
      configService: configService,
      dynamoDbClient: dynamoDbClient,
    })
  )
  .use(getSessionByIdMiddleware({ sessionService: sessionService }))
  .use(setGovUkSigningJourneyIdMiddleware(logger));
