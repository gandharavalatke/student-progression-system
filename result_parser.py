import pandas as pd
import os

# 📌 Load semester file with auto header detection
def load_semester(path):
    raw = pd.read_excel(path, header=None)
    header_row = None
    for i, row in raw.iterrows():
        row_str = [str(c).strip().upper() for c in row.tolist()]
        if "NAME" in row_str and "CGPA" in row_str:
            header_row = i
            break
    if header_row is None:
        raise ValueError(f"❌ Could not find NAME and CGPA in {path}")

    df = pd.read_excel(path, skiprows=header_row)
    df.columns = [str(c).strip().upper() for c in df.columns]

    # Keep only NAME + CGPA
    df = df[["NAME", "CGPA"]].dropna(subset=["NAME"])
    df["NAME"] = df["NAME"].astype(str).str.strip().str.lstrip("/")

    # Replace "--" with NaN
    df["CGPA"] = df["CGPA"].replace("--", pd.NA)

    return df


def merge_results():
    base = "/Users/anjalichavan/Desktop/NBA_project"
    files = [f"sem{i}.xlsx" for i in range(1, 7)]  # 📌 till Sem6

    master = pd.DataFrame(columns=["Name", "Role"] + [f"Sem{i}" for i in range(1, 9)])
    cleared_set = set()

    summary_data = []
    prev_names = set()  # track for left students

    semwise_names = {}  # store names per sem for later reference

    for sem, filename in enumerate(files, start=1):
        path = os.path.join(base, filename)
        df = load_semester(path)

        sem_map = dict(zip(df["NAME"], df["CGPA"]))
        names_in_file = set(df["NAME"])
        semwise_names[sem] = names_in_file
        total_students = len(names_in_file)

        if sem == 1:
            df_out = pd.DataFrame({"Name": df["NAME"], "Role": "Regular"})
            for i in range(1, 9):
                df_out[f"Sem{i}"] = pd.NA
            df_out[f"Sem{sem}"] = df["CGPA"]

            master = pd.concat([master, df_out], ignore_index=True)

            cleared_set = set(df.loc[df["CGPA"].notna(), "NAME"])

        elif sem == 2:
            eligible = cleared_set
            cleared_now = {n for n in eligible if n in sem_map and pd.notna(sem_map[n])}
            master.loc[master["Name"].isin(cleared_now), f"Sem{sem}"] = master["Name"].map(sem_map)
            cleared_set = cleared_now

        elif sem == 3:
            known_names = set(master["Name"])
            dse_names = [n for n in names_in_file if n not in known_names]

            if dse_names:
                dse_rows = pd.DataFrame({"Name": dse_names, "Role": "DSE"})
                for i in range(1, 9):
                    dse_rows[f"Sem{i}"] = pd.NA
                master = pd.concat([master, dse_rows], ignore_index=True)

            eligible_regular = set(master.loc[master["Role"] == "Regular", "Name"]).intersection(cleared_set)
            regular_cleared = {n for n in eligible_regular if n in sem_map and pd.notna(sem_map[n])}
            dse_cleared = {n for n in dse_names if n in sem_map and pd.notna(sem_map[n])}

            master.loc[master["Name"].isin(regular_cleared | dse_cleared), f"Sem{sem}"] = master["Name"].map(sem_map)
            cleared_set = regular_cleared | dse_cleared

        elif sem >= 4:
            eligible = cleared_set
            cleared_now = {n for n in eligible if n in sem_map and pd.notna(sem_map[n])}
            master.loc[master["Name"].isin(cleared_now), f"Sem{sem}"] = master["Name"].map(sem_map)
            cleared_set = cleared_now

        # ✅ Summary calculations
        without_backlog = len(cleared_set)
        with_backlog = total_students - without_backlog

        left_students = 0
        if sem > 1:
            left_students = len(prev_names - names_in_file)

        avg_cgpa = df["CGPA"].dropna().astype(float).mean()

        print(
            f"✅ Sem {sem}: Total = {total_students}, Without Backlog = {without_backlog}, "
            f"With Backlog = {with_backlog}, Left Students = {left_students}, Avg CGPA = {avg_cgpa:.2f}"
        )

        summary_data.append([
            f"Sem {sem}",
            total_students,
            without_backlog,
            with_backlog,
            left_students,
            round(avg_cgpa, 2) if pd.notna(avg_cgpa) else None
        ])

        prev_names = names_in_file

    # ✅ Adjustment for Sem3: align with Sem4 student list
    if 3 in semwise_names and 4 in semwise_names:
        sem4_names = semwise_names[4]
        sem3_cgpas = master.loc[master["Name"].isin(sem4_names), "Sem3"].dropna().astype(float)

        sem3_total = len(sem4_names)
        sem3_without_backlog = sem3_cgpas.count()
        sem3_with_backlog = sem3_total - sem3_without_backlog
        sem3_avg = sem3_cgpas.mean()

        for row in summary_data:
            if row[0] == "Sem 3":
                row[1] = sem3_total
                row[2] = sem3_without_backlog
                row[3] = sem3_with_backlog
                row[5] = round(sem3_avg, 2) if pd.notna(sem3_avg) else None
                break

        # ✅ Fix Left Students for Sem4
        for row in summary_data:
            if row[0] == "Sem 4":
                row[4] = 0
                break

    # ✅ Add combined averages
    sem_avgs = {row[0]: row[-1] for row in summary_data if row[-1] is not None}

    combined_pairs = [("Sem 1", "Sem 2"),
                      ("Sem 3", "Sem 4"),
                      ("Sem 5", "Sem 6"),
                      ("Sem 7", "Sem 8")]

    for s1, s2 in combined_pairs:
        if s1 in sem_avgs and s2 in sem_avgs:
            combined_avg = (sem_avgs[s1] + sem_avgs[s2]) / 2
            summary_data.append([
                f"{s1}&{s2} Combined Avg",
                None, None, None, None,
                round(combined_avg, 2)
            ])

    # ✅ Sort DSE students in Sheet1 by surname (first word in Name)
    def get_surname(name):
        return str(name).strip().split()[0] if pd.notna(name) else ""

    regular_df = master[master["Role"] == "Regular"]
    dse_df = master[master["Role"] == "DSE"].copy()
    dse_df["surname_key"] = dse_df["Name"].apply(get_surname)
    dse_df = dse_df.sort_values(by="surname_key").drop(columns=["surname_key"])

    master = pd.concat([regular_df, dse_df], ignore_index=True)

    return master, summary_data


if __name__ == "__main__":
    nba_result, summary_data = merge_results()

    out_path = "/Users/anjalichavan/Desktop/NBA_project/NBA_Result_Format.xlsx"
    with pd.ExcelWriter(out_path, engine="openpyxl") as writer:
        nba_result.to_excel(writer, sheet_name="Sheet1", index=False)
        summary_df = pd.DataFrame(
            summary_data,
            columns=["Semester", "Total Students", "Without Backlog", "With Backlog", "Left Students", "Avg CGPA"]
        )
        summary_df.to_excel(writer, sheet_name="Sheet2", index=False)

    print(f"✅ NBA format generated: {out_path}")
