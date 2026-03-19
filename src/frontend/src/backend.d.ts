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
export interface UserProfile {
    username: string;
}
export enum UserRole {
    admin = "admin",
    user = "user",
    guest = "guest"
}
export interface backendInterface {
    assignCallerUserRole(user: Principal, role: UserRole): Promise<void>;
    deleteUser(username: string): Promise<void>;
    getCallerUserProfile(): Promise<UserProfile | null>;
    getCallerUserRole(): Promise<UserRole>;
    getConversation(user1: UserId, user2: UserId): Promise<Array<Message>>;
    getMessage(messageId: MessageId): Promise<Message | null>;
    getPublicKey(username: string): Promise<PublicKey | null>;
    getUserProfile(user: Principal): Promise<UserProfile | null>;
    grantUserRole(userPrincipal: Principal): Promise<void>;
    isCallerAdmin(): Promise<boolean>;
    listUsers(): Promise<Array<string>>;
    loginUser(username: string, passwordHash: string): Promise<boolean>;
    purgeExpiredMessages(): Promise<bigint>;
    registerUser(username: string, passwordHash: string): Promise<void>;
    saveCallerUserProfile(profile: UserProfile): Promise<void>;
    sendMessage(sender: UserId, recipient: UserId, content: string, isImage: boolean): Promise<MessageId>;
    storePublicKey(username: string, publicKey: PublicKey): Promise<void>;
    unsendMessage(messageId: MessageId): Promise<void>;
    userExists(username: string): Promise<boolean>;
}
