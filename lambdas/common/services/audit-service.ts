import { SQSClient, SendMessageCommand } from "@aws-sdk/client-sqs";
import {
  AuditEvent,
  AuditEventContext,
  AuditEventSession,
  AuditEventType,
  AuditEventUser,
} from "../../types/audit-event";
import { CriAuditConfig } from "../../types/cri-audit-config";
import { SessionItem } from "../../types/session-item";

export class AuditService {
  private auditConfig: CriAuditConfig | undefined;
  constructor(
    private readonly getConfigEntry: () => string,
    private readonly sqsClient: SQSClient
  ) {}

  public async sendAuditEvent(
    eventType: AuditEventType,
    context: AuditEventContext
  ) {
    if (!this.auditConfig) {
      this.auditConfig = this.getAuditConfig();
    }
    const auditEvent = this.createAuditEvent(eventType, context);
    await this.sendAuditEventToQueue(auditEvent);
  }

  public getAuditConfig(): CriAuditConfig {
    const auditEventNamePrefix = process.env["SQS_AUDIT_EVENT_PREFIX"];
    if (!auditEventNamePrefix) {
      throw new Error("Missing environment variable: SQS_AUDIT_EVENT_PREFIX");
    }
    const queueUrl = process.env["SQS_AUDIT_EVENT_QUEUE_URL"];
    if (!queueUrl) {
      throw new Error(
        "Missing environment variable: SQS_AUDIT_EVENT_QUEUE_URL"
      );
    }
    const issuer = this.getConfigEntry();
    return {
      auditEventNamePrefix,
      issuer,
      queueUrl,
    };
  }

  private createAuditEvent(
    eventType: AuditEventType,
    context: AuditEventContext
  ): AuditEvent {
    if (!eventType) {
      throw new Error("Audit event type not specified");
    }
    const auditEventUser: AuditEventUser = this.createAuditEventUser(
      context.sessionItem,
      context.clientIpAddress
    );
    return {
      component_id: this.auditConfig?.issuer as string,
      event_name: `${this.auditConfig?.auditEventNamePrefix}_${eventType}`,
      extensions: context?.extensions ?? undefined,
      restricted: context?.personIdentity ?? undefined,
      timestamp: Math.floor(Date.now() / 1000),
      user: auditEventUser,
    };
  }

  private createAuditEventUser(
    sessionItem: AuditEventSession,
    clientIpAddress: string | undefined
  ): AuditEventUser {
    return {
      govuk_signin_journey_id: sessionItem?.clientSessionId ?? undefined,
      ip_address: clientIpAddress,
      persistent_session_id: sessionItem?.persistentSessionId ?? undefined,
      session_id: sessionItem?.sessionId ?? undefined,
      user_id: sessionItem?.subject ?? undefined,
    };
  }

  private async sendAuditEventToQueue(auditEvent: AuditEvent) {
    const sendMsgCommand = new SendMessageCommand({
      MessageBody: JSON.stringify(auditEvent),
      QueueUrl: this.auditConfig?.queueUrl as string,
    });
    await this.sqsClient.send(sendMsgCommand);
  }

  public createAuditEventContext(
    sessionItem: SessionItem,
    extensions?: Record<string, string>
  ): AuditEventContext {
    const context = {
      sessionItem: {
        sessionId: sessionItem.sessionId,
        subject: sessionItem.subject,
        persistentSessionId: sessionItem.persistentSessionId,
        clientSessionId: sessionItem.clientSessionId,
      },
      clientIpAddress: sessionItem.clientIpAddress,
    };
    if (extensions) {
      return {
        ...context,
        extensions: extensions,
      };
    }
    return context;
  }
}
