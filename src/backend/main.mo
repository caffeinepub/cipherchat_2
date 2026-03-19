import Runtime "mo:core/Runtime";
import Text "mo:core/Text";
import Map "mo:core/Map";
import Nat "mo:core/Nat";
import Time "mo:core/Time";
import Principal "mo:core/Principal";
import Storage "blob-storage/Storage";
import MixinStorage "blob-storage/Mixin";
import MixinAuthorization "authorization/MixinAuthorization";
import AccessControl "authorization/access-control";

actor {
  // Keep accessControlState and MixinAuthorization to preserve stable variable
  // compatibility with previous deployment (cannot be dropped without migration).
  let accessControlState = AccessControl.initState();
  include MixinAuthorization(accessControlState);
  include MixinStorage();

  // Types
  type UserId = Text;
  type MessageId = Nat;

  public type User = {
    username : Text;
    passwordHash : Text;
  };

  public type Message = {
    id : MessageId;
    sender : UserId;
    recipient : UserId;
    content : Text;
    timestamp : Time.Time;
    isImage : Bool;
  };

  public type PublicKey = Text;

  public type UserProfile = {
    username : Text;
  };

  // 24 hours in nanoseconds
  let twentyFourHours : Int = 24 * 60 * 60 * 1_000_000_000;

  // Persistent state
  let users = Map.empty<UserId, User>();
  let messages = Map.empty<MessageId, Message>();
  let publicKeys = Map.empty<UserId, PublicKey>();

  // Kept for stable variable compatibility with previous deployment
  let userPrincipals = Map.empty<Principal, UserId>();
  let userProfiles = Map.empty<Principal, UserProfile>();

  var nextMessageId = 0;
  var nextImageId = 0; // kept for stable variable compatibility

  // Helper: verify credentials, trap if invalid
  func verifyCredentials(username : Text, passwordHash : Text) {
    switch (users.get(username)) {
      case (null) { Runtime.trap("Invalid credentials") };
      case (?user) {
        if (user.passwordHash != passwordHash) {
          Runtime.trap("Invalid credentials");
        };
      };
    };
  };

  // Register a new user
  public shared func registerUser(username : Text, passwordHash : Text) : async () {
    switch (users.get(username)) {
      case (null) {
        let user : User = { username; passwordHash };
        users.add(username, user);
      };
      case (?_) { Runtime.trap("Username already taken") };
    };
  };

  // Login: verify credentials and return success
  public shared func loginUser(username : Text, passwordHash : Text) : async Bool {
    switch (users.get(username)) {
      case (null) { false };
      case (?user) { user.passwordHash == passwordHash };
    };
  };

  // List all registered users - public, no auth needed
  public query func listUsers() : async [Text] {
    users.keys().toArray();
  };

  // Check if a user exists
  public query func userExists(username : Text) : async Bool {
    users.containsKey(username);
  };

  // Store public key - verified by password
  public shared func storePublicKey(username : Text, passwordHash : Text, publicKey : PublicKey) : async () {
    verifyCredentials(username, passwordHash);
    switch (users.get(username)) {
      case (null) { Runtime.trap("User does not exist") };
      case (?_) { publicKeys.add(username, publicKey) };
    };
  };

  // Get a user's public key - public, no auth needed
  public query func getPublicKey(username : Text) : async ?PublicKey {
    publicKeys.get(username);
  };

  // Send a message - verified by sender's password
  public shared func sendMessage(sender : UserId, senderPasswordHash : Text, recipient : UserId, content : Text, isImage : Bool) : async MessageId {
    verifyCredentials(sender, senderPasswordHash);
    switch (users.get(recipient)) {
      case (null) { Runtime.trap("Recipient does not exist") };
      case (?_) {
        let messageId = nextMessageId;
        let message : Message = {
          id = messageId;
          sender;
          recipient;
          content;
          timestamp = Time.now();
          isImage;
        };
        messages.add(messageId, message);
        nextMessageId += 1;
        messageId;
      };
    };
  };

  // Unsend a message - verified by sender's password
  public shared func unsendMessage(messageId : MessageId, username : Text, passwordHash : Text) : async () {
    verifyCredentials(username, passwordHash);
    switch (messages.get(messageId)) {
      case (null) { Runtime.trap("Message does not exist") };
      case (?message) {
        if (message.sender != username) {
          Runtime.trap("Unauthorized: You can only unsend your own messages");
        };
        messages.remove(messageId);
      };
    };
  };

  // Purge all messages older than 24 hours - open call
  public shared func purgeExpiredMessages() : async Nat {
    let cutoff : Int = Time.now() - twentyFourHours;
    var purged = 0;
    messages.entries().forEach(func((id, message)) {
      if (message.timestamp < cutoff) {
        messages.remove(id);
        purged += 1;
      };
    });
    purged;
  };

  // Get all messages between two users (last 24 hours) - public
  public query func getConversation(user1 : UserId, user2 : UserId) : async [Message] {
    let cutoff : Int = Time.now() - twentyFourHours;
    messages.values().toArray().filter(func(m) {
      ((m.sender == user1 and m.recipient == user2) or (m.sender == user2 and m.recipient == user1))
      and m.timestamp >= cutoff
    });
  };
};
