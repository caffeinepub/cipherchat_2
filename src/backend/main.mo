import Runtime "mo:core/Runtime";
import Iter "mo:core/Iter";
import Text "mo:core/Text";
import Map "mo:core/Map";
import Nat "mo:core/Nat";
import Time "mo:core/Time";
import Array "mo:core/Array";
import List "mo:core/List";
import Principal "mo:core/Principal";
import Storage "blob-storage/Storage";
import MixinStorage "blob-storage/Mixin";

import MixinAuthorization "authorization/MixinAuthorization";
import AccessControl "authorization/access-control";


actor {
  let accessControlState = AccessControl.initState();
  include MixinAuthorization(accessControlState);
  include MixinStorage();

  // Types
  type UserId = Text;
  type MessageId = Nat;
  type ImageId = Nat;

  public type User = {
    username : Text;
    passwordHash : Text;
  };

  public type Message = {
    id : MessageId;
    sender : UserId;
    recipient : UserId;
    content : Text; // Encrypted text or JSON string with image reference
    timestamp : Time.Time;
    isImage : Bool;
  };

  public type PublicKey = Text;

  public type UserProfile = {
    username : Text;
  };

  public type EncryptedImage = {
    id : ImageId;
    contentType : Text;
    fileName : Text;
    content : Storage.ExternalBlob;
    uploader : UserId;
    timestamp : Time.Time;
  };

  // 24 hours in nanoseconds
  let twentyFourHours : Int = 24 * 60 * 60 * 1_000_000_000;

  // Persistent state
  let users = Map.empty<UserId, User>();
  let messages = Map.empty<MessageId, Message>();
  let userPrincipals = Map.empty<Principal, UserId>();
  let userProfiles = Map.empty<Principal, UserProfile>();
  let publicKeys = Map.empty<UserId, PublicKey>();

  var nextMessageId = 0;
  var nextImageId = 0;

  // User profile management (required by frontend)
  public query ({ caller }) func getCallerUserProfile() : async ?UserProfile {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can view profiles");
    };
    userProfiles.get(caller);
  };

  public query ({ caller }) func getUserProfile(user : Principal) : async ?UserProfile {
    if (caller != user and not AccessControl.isAdmin(accessControlState, caller)) {
      Runtime.trap("Unauthorized: Can only view your own profile");
    };
    userProfiles.get(user);
  };

  public shared ({ caller }) func saveCallerUserProfile(profile : UserProfile) : async () {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can save profiles");
    };
    userProfiles.add(caller, profile);
  };

  // Register a new user - open to guests, but they need admin to grant them user role afterward
  public shared ({ caller }) func registerUser(username : Text, passwordHash : Text) : async () {
    // Registration is open to anyone (guests can register)
    // Check if username already exists
    switch (users.get(username)) {
      case (null) {
        let user : User = {
          username;
          passwordHash;
        };
        users.add(username, user);
        userPrincipals.add(caller, username);

        // Create default profile (but user won't have access until role is assigned)
        let profile : UserProfile = {
          username = username;
        };
        userProfiles.add(caller, profile);
        // Automatically grant user role so they can use the app immediately
        accessControlState.userRoles.add(caller, #user);
      };
      case (?_) { Runtime.trap("Username already taken") };
    };
  };

  // Admin function to grant user role after registration
  public shared ({ caller }) func grantUserRole(userPrincipal : Principal) : async () {
    if (not (AccessControl.isAdmin(accessControlState, caller))) {
      Runtime.trap("Unauthorized: Only admins can grant user roles");
    };
    AccessControl.assignRole(accessControlState, caller, userPrincipal, #user);
  };

  // Validate user credentials for login
  public query func loginUser(username : Text, passwordHash : Text) : async Bool {
    // Login is open to anyone (guests can attempt to login)
    switch (users.get(username)) {
      case (null) { false };
      case (?user) { user.passwordHash == passwordHash };
    };
  };

  // List all registered users (usernames only)
  public query ({ caller }) func listUsers() : async [Text] {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can list users");
    };
    users.keys().toArray();
  };

  // Send a message from one user to another
  public shared ({ caller }) func sendMessage(sender : UserId, recipient : UserId, content : Text, isImage : Bool) : async MessageId {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can send messages");
    };

    // Verify the caller is the sender
    switch (userPrincipals.get(caller)) {
      case (null) { Runtime.trap("Caller is not associated with any user account") };
      case (?callerUsername) {
        if (callerUsername != sender) {
          Runtime.trap("Unauthorized: You can only send messages as yourself");
        };
      };
    };

    // Ensure sender exists
    switch (users.get(sender)) {
      case (null) { Runtime.trap("Sender does not exist") };
      case (?_) {
        // Ensure recipient exists
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
    };
  };

  // Unsend a message - only the sender can unsend, removes from both views
  public shared ({ caller }) func unsendMessage(messageId : MessageId) : async () {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can unsend messages");
    };

    switch (messages.get(messageId)) {
      case (null) { Runtime.trap("Message does not exist") };
      case (?message) {
        // Verify the caller is the sender
        switch (userPrincipals.get(caller)) {
          case (null) { Runtime.trap("Caller is not associated with any user account") };
          case (?callerUsername) {
            if (callerUsername != message.sender) {
              Runtime.trap("Unauthorized: You can only unsend your own messages");
            };
            messages.remove(messageId);
          };
        };
      };
    };
  };

  // Purge all messages older than 24 hours (can be called by any authenticated user)
  public shared ({ caller }) func purgeExpiredMessages() : async Nat {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can purge expired messages");
    };

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

  // Get all messages between two users (filters out messages older than 24 hours)
  public query ({ caller }) func getConversation(user1 : UserId, user2 : UserId) : async [Message] {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can view conversations");
    };

    // Verify the caller is one of the participants or an admin
    if (not AccessControl.isAdmin(accessControlState, caller)) {
      switch (userPrincipals.get(caller)) {
        case (null) { Runtime.trap("Caller is not associated with any user account") };
        case (?callerUsername) {
          if (callerUsername != user1 and callerUsername != user2) {
            Runtime.trap("Unauthorized: You can only view your own conversations");
          };
        };
      };
    };

    let cutoff : Int = Time.now() - twentyFourHours;
    messages.values().toArray().filter(func(m) {
      ((m.sender == user1 and m.recipient == user2) or (m.sender == user2 and m.recipient == user1))
      and m.timestamp >= cutoff
    });
  };

  // Delete a user account and all related messages
  public shared ({ caller }) func deleteUser(username : Text) : async () {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can delete accounts");
    };

    // Verify the caller is deleting their own account or is an admin
    if (not AccessControl.isAdmin(accessControlState, caller)) {
      switch (userPrincipals.get(caller)) {
        case (null) { Runtime.trap("Caller is not associated with any user account") };
        case (?callerUsername) {
          if (callerUsername != username) {
            Runtime.trap("Unauthorized: You can only delete your own account");
          };
        };
      };
    };

    switch (users.get(username)) {
      case (null) { Runtime.trap("User does not exist") };
      case (?_) {
        // Remove messages sent or received by the user
        messages.entries().forEach(func((id, message)) { if (message.sender == username or message.recipient == username) { messages.remove(id) } });
        // Remove user from map
        users.remove(username);
        // Remove principal mapping
        userPrincipals.remove(caller);
        // Remove profile
        userProfiles.remove(caller);
        // Remove public key
        publicKeys.remove(username);
      };
    };
  };

  // Check if a user exists
  public query func userExists(username : Text) : async Bool {
    // Open to all - needed for signup flow before user has a role
    users.containsKey(username);
  };

  public query ({ caller }) func getMessage(messageId : MessageId) : async ?Message {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can view messages");
    };

    switch (messages.get(messageId)) {
      case (null) { null };
      case (?message) {
        // Verify the caller is sender, recipient, or admin
        if (not AccessControl.isAdmin(accessControlState, caller)) {
          switch (userPrincipals.get(caller)) {
            case (null) { Runtime.trap("Caller is not associated with any user account") };
            case (?callerUsername) {
              if (callerUsername != message.sender and callerUsername != message.recipient) {
                Runtime.trap("Unauthorized: You can only view your own messages");
              };
            };
          };
        };
        ?message;
      };
    };
  };

  // Store the caller's public key
  public shared ({ caller }) func storePublicKey(username : Text, publicKey : PublicKey) : async () {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can store public keys");
    };

    // Verify the caller is the user
    switch (userPrincipals.get(caller)) {
      case (null) { Runtime.trap("Caller is not associated with any user account") };
      case (?callerUsername) {
        if (callerUsername != username) {
          Runtime.trap("Unauthorized: You can only store your own public key");
        };
      };
    };

    switch (users.get(username)) {
      case (null) { Runtime.trap("User does not exist") };
      case (?_) { publicKeys.add(username, publicKey) };
    };
  };

  // Get a user's public key
  public query ({ caller }) func getPublicKey(username : Text) : async ?PublicKey {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can get public keys");
    };

    switch (users.get(username)) {
      case (null) { Runtime.trap("User does not exist") };
      case (?_) { publicKeys.get(username) };
    };
  };
};
