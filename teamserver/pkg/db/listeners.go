package db

import (
	"log"
)

func (db *DB) ListenerAdd(Name, Protocol, Config string) error {
	// Use INSERT OR REPLACE so that:
	//   - A brand-new listener is inserted.
	//   - A listener that already exists (same Name, because Name is UNIQUE)
	//     is replaced with the new config — this handles the case where the
	//     teamserver restarts and re-creates the same listener from the profile
	//     or when a user creates a listener with a name that was previously used.
	stmt, err := db.db.Prepare("INSERT OR REPLACE INTO TS_Listeners (Name, Protocol, Config) VALUES (?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(Name, Protocol, Config)
	return err
}

func (db *DB) ListenerExist(Name string) bool {
	query, err := db.db.Query("SELECT Name FROM TS_Listeners")
	if err != nil {
		return false
	}
	defer query.Close()

	for query.Next() {
		var QueryName string

		query.Scan(&QueryName)

		if Name == QueryName {
			return true
		}
	}

	return false
}

func (db *DB) ListenerAll() []map[string]string {

	var Listeners []map[string]string

	query, err := db.db.Query("SELECT Name, Protocol, Config FROM TS_Listeners")
	if err != nil {
		return nil
	}
	defer query.Close()

	for query.Next() {

		var (
			Name string
			Prot string
			Conf string
			Data map[string]string
		)

		/* read the selected items */
		err = query.Scan(&Name, &Prot, &Conf)
		if err != nil {
			/* at this point we failed
			 * just return the collected listeners */
			return Listeners
		}

		Data = map[string]string{
			"Name":     Name,
			"Protocol": Prot,
			"Config":   Conf,
		}

		/* append collected listener to listener array */
		Listeners = append(Listeners, Data)

	}

	return Listeners
}

func (db *DB) ListenerCount() int {

	var Count int

	query, err := db.db.Query("SELECT COUNT(*) FROM TS_Listeners")
	if err != nil {
		return 0
	}
	defer query.Close()

	for query.Next() {
		if err = query.Scan(&Count); err != nil {
			log.Fatal(err)
		}
	}

	return Count
}

func (db *DB) ListenerNames() []string {
	var (
		Name  string
		Names []string
	)

	query, err := db.db.Query("SELECT Name FROM TS_Listeners")
	if err != nil {
		return nil
	}

	defer query.Close()

	for query.Next() {

		if err = query.Scan(&Name); err != nil {
			return Names
		}

		Names = append(Names, Name)

	}

	return Names
}

func (db *DB) ListenerRemove(Name string) error {
	// prepare some arguments to execute for the sqlite db
	stmt, err := db.db.Prepare("DELETE FROM TS_Listeners WHERE Name = ?")
	if err != nil {
		return err
	}

	// execute statement
	_, err = stmt.Exec(Name)
	stmt.Close()

	if err != nil {
		return err
	}

	return nil
}
