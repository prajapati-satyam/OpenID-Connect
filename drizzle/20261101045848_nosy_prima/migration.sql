CREATE TABLE "users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	"first_name" varchar(50) NOT NULL,
	"last_name" varchar(50),
	"email" varchar(35) UNIQUE,
	"password" varchar(256),
	"salt" text
);
