import { pgTable, uuid, varchar, text} from "drizzle-orm/pg-core";

export const usersTable = pgTable("users", {
  id: uuid('id').primaryKey().defaultRandom(),
  first_name: varchar("first_name", {length: 50}).notNull(),
  last_name: varchar("last_name", {length: 50}),
  email: varchar("email", {length: 35}).unique(),
  password: varchar("password", {length: 256}),
  salt: text("salt")
});
