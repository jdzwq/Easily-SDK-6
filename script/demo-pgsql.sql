
\connect demo;

drop table if exists dogs;
create table dogs(
    did varchar(50),
    dname varchar(100),
    dage date,
    dprice numeric(10,2)
);

drop table if exists cats;
create table cats(
	cid varchar(50) NOT NULL,
	cdoc text NULL
);

drop table if exists pigs;
create table pigs(
	pid varchar(50) NOT NULL,
	pdoc BYTEA NULL
);

drop table if exists docs;
create table docs(
	xid varchar(50) NOt NULL,
	xdoc text NULL
);
