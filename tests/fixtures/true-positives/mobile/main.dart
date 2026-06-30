// True-positive fixtures for mobile Dart patterns
import 'package:shared_preferences/shared_preferences.dart';

Future<void> storeAuth() async {
  SharedPreferences.getInstance().then((p) => p.setString('auth_token', token));
}
