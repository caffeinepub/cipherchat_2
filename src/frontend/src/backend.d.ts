import type { Principal } from "@icp-sdk/core/principal";
export interface Some<T> {
    __kind__: "Some";
    value: T;
}
export interface None {
    __kind__: "None";
}
export type Option<T> = Some<T> | None;
export type PublicKey = string;
export type UserId = string;
export type Time = bigint;
export type MessageId = bigint;
export interface Message {
    id: MessageId;
    content: string;
    recipient: UserId;
    isImage: boolean;
    sender: UserId;
    timestamp: Time;
}
export interface backendInterface {
    getConversation(user1: UserId, user2: UserId): Promise<Array<Message>>;
    getPublicKey(username: string): Promise<PublicKey | null>;
    listUsers(): Promise<Array<string>>;
    loginUser(username: string, passwordHash: string): Promise<boolean>;
    purgeExpiredMessages(): Promise<bigint>;
    registerUser(username: string, passwordHash: string): Promise<void>;
    sendMessage(sender: UserId, senderPasswordHash: string, recipient: UserId, content: string, isImage: boolean): Promise<MessageId>;
    storePublicKey(username: string, passwordHash: string, publicKey: PublicKey): Promise<void>;
    unsendMessage(messageId: MessageId, username: string, passwordHash: string): Promise<void>;
    userExists(username: string): Promise<boolean>;
}
