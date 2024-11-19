from utils import Utils

# Print a string with a title and warning style

Utils.pretty_print("This is a warning message", title="Warning", style="warning")

# Print a list as a table

my_list = [1, 2, 3, 4, 5]
Utils.pretty_print(my_list, as_table=True, table_title="My List")

# Print a dictionary

my_dict = {"name": "Alice", "age": 30, "city": "New York"}
Utils.pretty_print(my_dict, title="User Info", style="info")

# Print a status message

Utils.print_status("Operation completed successfully.", level="success")

# Generate and print random data

random_data = Utils.generate_random_data(num_items=5, data_type="dict")
Utils.pretty_print(random_data, title="Random Data", as_table=True) # Print in a table
