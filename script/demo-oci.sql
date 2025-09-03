
drop table dogs purge;
create table dogs(
    did varchar(50),
    dname varchar(100),
    dage date,
    dprice numeric(10,2)
);

drop table cats purge;
create table cats(
	cid varchar(50) NOT NULL,
	cdoc text NULL
);

drop table pigs purge;
create table pigs(
	pid varchar(50) NOT NULL,
	pdoc blob NULL
);

drop table docs purge;
create table docs(
	xid varchar(50) NOt NULL,
	xdoc text NULL
);


